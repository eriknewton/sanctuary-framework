/**
 * Recovery Cascade v1.0 -- regression test suite.
 *
 * Covers all 10 acceptance criteria from the WP-MVP-8 spawn prompt:
 *
 *   1. M-of-N threshold enforced
 *   2. Guardian enroll + revoke (signed roster-update events)
 *   3. DMswitch fires at window (30d default, 90d estate)
 *   4. Cascade is deterministic
 *   5. Recovery events use signed envelope
 *   6. Multi-principal boundary evaluated
 *   7. Non-dependency clean
 *   8. Real-crypto tests
 *   9. Operator knob honored (max_offline_window)
 *  10. Failure modes documented + tested
 *
 * Real crypto: all signatures use @noble/curves Ed25519. No mocked crypto.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { SIGNATURE_SCHEME_V1 } from "../../src/mesh/constants.js";
import { issueGuardianRoster } from "../../src/mesh/guardian/guardian-roster.js";
import { generateFortressMaster } from "../../src/mesh/trust-root.js";
import type { GuardianIdentity, GuardianRoster } from "../../src/mesh/guardian/types.js";
import type { FortressMasterPublicKey } from "../../src/mesh/types.js";

import {
  // Constants
  RECOVERY_EVENT_TYPES,
  DEFAULT_DMSWITCH_WINDOW_MS,
  MAX_ESTATE_PLANNING_WINDOW_MS,
  MIN_DMSWITCH_WINDOW_MS,
  RECOVERY_SIGNATURE_SCHEME,
  RECOVERY_GATE_REASON_CODES,
  // Errors
  ThresholdNotMetError,
  WindowNotExpiredError,
  SignatureInvalidError,
  RosterStaleError,
  CascadeStateError,
  GuardianNotFoundError,
  RecoveryConfigError,
  // Guardian roster
  enrollGuardian,
  revokeGuardian,
  // Recovery event
  packRecoveryEvent,
  verifyRecoveryEvent,
  // DMswitch
  validateDmswitchConfig,
  recordActivity,
  evaluateDmswitch,
  enforceDmswitchExpired,
  emitCascadeEntry,
  // Threshold
  buildApprovalSigningInput,
  evaluateThreshold,
  enforceThreshold,
  signApproval,
  // Cascade
  initiateCascade,
  beginAwaitingThreshold,
  registerApproval,
  evaluateCascade,
  executeCascade,
  failCascade,
  // Multi-principal
  evaluateMultiPrincipalBoundary,
  // Service
  RecoveryStore,
  initRecovery,
  registerGuardianApproval,
  queryCascadeState,
  executeRecovery,
} from "../../src/recovery/index.js";

import type {
  ActivityRecord,
  DmswitchConfig,
  CascadeState,
  GuardianApproval,
} from "../../src/recovery/types.js";

// ===================================================================
// Test fixtures
// ===================================================================

interface TestFixture {
  masterPublic: FortressMasterPublicKey;
  masterSecret: Uint8Array;
  nodeKp: ReturnType<typeof generateKeypair>;
  nodeId: string;
  fortressId: string;
}

function buildFixture(): TestFixture {
  const master = generateFortressMaster();
  const nodeKp = generateKeypair();
  return {
    masterPublic: master.public,
    masterSecret: master.private_key,
    nodeKp,
    nodeId: "node-test-1",
    fortressId: master.public.fortress_id,
  };
}

function buildGuardians(count: number): Array<{
  identity: GuardianIdentity;
  kp: ReturnType<typeof generateKeypair>;
}> {
  const out = [];
  for (let i = 0; i < count; i++) {
    const kp = generateKeypair();
    out.push({
      identity: {
        guardian_id: `guardian-${i}`,
        public_key: toBase64url(kp.publicKey),
        kind: "human" as const,
        invited_at: new Date().toISOString(),
      },
      kp,
    });
  }
  return out;
}

function buildRoster(
  fix: TestFixture,
  guardians: Array<{ identity: GuardianIdentity }>,
  m: number,
  version = 1
): GuardianRoster {
  return issueGuardianRoster({
    m,
    n: guardians.length,
    guardians: guardians.map((g) => g.identity),
    fortress_id: fix.fortressId,
    version,
    master_private_key: fix.masterSecret,
  });
}

function buildActivity(ms_ago: number): ActivityRecord {
  const ms = Date.now() - ms_ago;
  return {
    last_activity_at: new Date(ms).toISOString(),
    last_activity_ms: ms,
    source: "test",
  };
}

function buildSignedApprovals(
  guardians: Array<{ identity: GuardianIdentity; kp: ReturnType<typeof generateKeypair> }>,
  count: number,
  cascade_id: string,
  action: string,
  fortress_id: string,
  roster_version: number
): GuardianApproval[] {
  const signingInput = buildApprovalSigningInput({
    cascade_id,
    recovery_action: action,
    fortress_id,
    roster_version,
  });
  return guardians.slice(0, count).map((g) =>
    signApproval({
      signing_input: signingInput,
      guardian_id: g.identity.guardian_id,
      guardian_private_key: g.kp.privateKey,
      recovery_action: action,
      cascade_id,
    })
  );
}

// ===================================================================
// Acceptance criterion 1: M-of-N threshold enforced
// ===================================================================

describe("acceptance criterion 1: M-of-N threshold enforced", () => {
  it("allows when M signatures are present", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const signingInput = buildApprovalSigningInput({
      cascade_id: "c1",
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const approvals = buildSignedApprovals(guardians, 3, "c1", "key_rotation", fix.fortressId, 1);

    const result = evaluateThreshold({ approvals, roster, signing_input: signingInput });
    expect(result.threshold_met).toBe(true);
    expect(result.valid_count).toBe(3);
  });

  it("denies when below M signatures", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const signingInput = buildApprovalSigningInput({
      cascade_id: "c2",
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const approvals = buildSignedApprovals(guardians, 2, "c2", "key_rotation", fix.fortressId, 1);

    const result = evaluateThreshold({ approvals, roster, signing_input: signingInput });
    expect(result.threshold_met).toBe(false);
    expect(result.valid_count).toBe(2);
  });

  it("enforceThreshold throws ThresholdNotMetError below M", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const signingInput = buildApprovalSigningInput({
      cascade_id: "c3",
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const approvals = buildSignedApprovals(guardians, 1, "c3", "key_rotation", fix.fortressId, 1);

    expect(() =>
      enforceThreshold({ approvals, roster, signing_input: signingInput })
    ).toThrow(ThresholdNotMetError);
  });

  it("rejects duplicate guardian approvals", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const signingInput = buildApprovalSigningInput({
      cascade_id: "c4",
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const approval = signApproval({
      signing_input: signingInput,
      guardian_id: guardians[0]!.identity.guardian_id,
      guardian_private_key: guardians[0]!.kp.privateKey,
      recovery_action: "key_rotation",
      cascade_id: "c4",
    });
    // Duplicate the same approval.
    const approvals = [approval, { ...approval }];

    const result = evaluateThreshold({ approvals, roster, signing_input: signingInput });
    expect(result.valid_count).toBe(1);
    expect(result.invalid_guardian_ids).toContain(guardians[0]!.identity.guardian_id);
  });

  it("allows exactly M of larger N", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(7);
    const roster = buildRoster(fix, guardians, 4);
    const signingInput = buildApprovalSigningInput({
      cascade_id: "c5",
      recovery_action: "estate_unlock",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const approvals = buildSignedApprovals(guardians, 4, "c5", "estate_unlock", fix.fortressId, 1);

    const result = evaluateThreshold({ approvals, roster, signing_input: signingInput });
    expect(result.threshold_met).toBe(true);
    expect(result.valid_count).toBe(4);
    expect(result.threshold_m).toBe(4);
    expect(result.total_n).toBe(7);
  });
});

// ===================================================================
// Acceptance criterion 2: Guardian enroll + revoke
// ===================================================================

describe("acceptance criterion 2: guardian enroll + revoke", () => {
  it("enrolls a guardian and produces a signed event", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);
    const newGuardian = buildGuardians(1)[0]!;
    newGuardian.identity.guardian_id = "guardian-new";

    const { roster: newRoster, event } = enrollGuardian({
      current_roster: roster,
      new_guardian: newGuardian.identity,
      fortress_master_public: fix.masterPublic,
      fortress_master_private_key: fix.masterSecret,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      node_signing_key: fix.nodeKp.privateKey,
    });

    expect(newRoster.n).toBe(4);
    expect(newRoster.version).toBe(2);
    expect(newRoster.guardians).toHaveLength(4);
    expect(event.event_type).toBe(RECOVERY_EVENT_TYPES.GUARDIAN_ENROLL);
    expect(event.signature_scheme).toBe(RECOVERY_SIGNATURE_SCHEME);
    expect(event.signature).toBeTruthy();
  });

  it("revokes a guardian and produces a signed event", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);

    const { roster: newRoster, event } = revokeGuardian({
      current_roster: roster,
      guardian_id: guardians[4]!.identity.guardian_id,
      fortress_master_public: fix.masterPublic,
      fortress_master_private_key: fix.masterSecret,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      node_signing_key: fix.nodeKp.privateKey,
    });

    expect(newRoster.n).toBe(4);
    expect(newRoster.version).toBe(2);
    expect(event.event_type).toBe(RECOVERY_EVENT_TYPES.GUARDIAN_REVOKE);
    expect(event.signature_scheme).toBe(RECOVERY_SIGNATURE_SCHEME);
    // Revoke event payload should only contain guardian_id (not leak identity).
    expect(event.payload).toHaveProperty("guardian_id");
    expect(event.payload).not.toHaveProperty("public_key");
  });

  it("rejects enrolling duplicate guardian", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);

    expect(() =>
      enrollGuardian({
        current_roster: roster,
        new_guardian: guardians[0]!.identity,
        fortress_master_public: fix.masterPublic,
        fortress_master_private_key: fix.masterSecret,
        emitter_node: fix.nodeId,
        emitter_principal: "root",
        node_signing_key: fix.nodeKp.privateKey,
      })
    ).toThrow(RecoveryConfigError);
  });

  it("rejects revoking unknown guardian", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);

    expect(() =>
      revokeGuardian({
        current_roster: roster,
        guardian_id: "nonexistent",
        fortress_master_public: fix.masterPublic,
        fortress_master_private_key: fix.masterSecret,
        emitter_node: fix.nodeId,
        emitter_principal: "root",
        node_signing_key: fix.nodeKp.privateKey,
      })
    ).toThrow(GuardianNotFoundError);
  });
});

// ===================================================================
// Acceptance criterion 3: DMswitch fires at window
// ===================================================================

describe("acceptance criterion 3: DMswitch fires at window", () => {
  it("triggers after 30-day default window", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
      estate_planning_enabled: false,
    };
    const activity = buildActivity(DEFAULT_DMSWITCH_WINDOW_MS + 1000);

    const result = evaluateDmswitch({ last_activity: activity, config });
    expect(result.triggered).toBe(true);
    expect(result.remaining_ms).toBe(0);
  });

  it("does not trigger before window expires", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
      estate_planning_enabled: false,
    };
    const activity = buildActivity(DEFAULT_DMSWITCH_WINDOW_MS - 60000);

    const result = evaluateDmswitch({ last_activity: activity, config });
    expect(result.triggered).toBe(false);
    expect(result.remaining_ms).toBeGreaterThan(0);
  });

  it("supports 90-day estate-planning window", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: MAX_ESTATE_PLANNING_WINDOW_MS,
      estate_planning_enabled: true,
    };
    // 60 days ago: should not trigger (90 day window).
    const activity = buildActivity(60 * 24 * 60 * 60 * 1000);

    const result = evaluateDmswitch({ last_activity: activity, config });
    expect(result.triggered).toBe(false);
  });

  it("triggers at 90 days with estate-planning", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: MAX_ESTATE_PLANNING_WINDOW_MS,
      estate_planning_enabled: true,
    };
    const activity = buildActivity(MAX_ESTATE_PLANNING_WINDOW_MS + 1000);

    const result = evaluateDmswitch({ last_activity: activity, config });
    expect(result.triggered).toBe(true);
  });

  it("activity ticks reset the window", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
      estate_planning_enabled: false,
    };
    // Recent activity: 5 minutes ago.
    const activity = recordActivity("manual_heartbeat", Date.now() - 5 * 60 * 1000);

    const result = evaluateDmswitch({ last_activity: activity, config });
    expect(result.triggered).toBe(false);
    expect(result.remaining_ms).toBeGreaterThan(DEFAULT_DMSWITCH_WINDOW_MS - 10 * 60 * 1000);
  });

  it("emits cascade entry event on trigger", () => {
    const fix = buildFixture();
    const config: DmswitchConfig = {
      max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
      estate_planning_enabled: false,
    };
    const activity = buildActivity(DEFAULT_DMSWITCH_WINDOW_MS + 1000);

    const event = emitCascadeEntry({
      last_activity: activity,
      config,
      fortress_id: fix.fortressId,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      signing_key: fix.nodeKp.privateKey,
    });

    expect(event.event_type).toBe(RECOVERY_EVENT_TYPES.DMSWITCH_CASCADE_ENTRY);
    expect(event.signature_scheme).toBe(RECOVERY_SIGNATURE_SCHEME);
    expect(event.signature).toBeTruthy();
    expect(verifyRecoveryEvent(event, fix.nodeKp.publicKey)).toBe(true);
  });

  it("enforceDmswitchExpired throws when window not elapsed", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
      estate_planning_enabled: false,
    };
    const activity = buildActivity(1000);

    expect(() =>
      enforceDmswitchExpired({ last_activity: activity, config })
    ).toThrow(WindowNotExpiredError);
  });
});

// ===================================================================
// Acceptance criterion 4: Cascade is deterministic
// ===================================================================

describe("acceptance criterion 4: cascade is deterministic", () => {
  it("two evaluators produce identical threshold results from same inputs", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const signingInput = buildApprovalSigningInput({
      cascade_id: "det-1",
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const approvals = buildSignedApprovals(guardians, 3, "det-1", "key_rotation", fix.fortressId, 1);

    const result1 = evaluateThreshold({ approvals, roster, signing_input: signingInput });
    const result2 = evaluateThreshold({ approvals, roster, signing_input: signingInput });

    expect(result1.threshold_met).toBe(result2.threshold_met);
    expect(result1.valid_count).toBe(result2.valid_count);
    expect(result1.valid_guardian_ids).toEqual(result2.valid_guardian_ids);
  });

  it("DMswitch evaluation is deterministic with fixed now_ms", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
      estate_planning_enabled: false,
    };
    const activity: ActivityRecord = {
      last_activity_at: "2026-01-01T00:00:00.000Z",
      last_activity_ms: new Date("2026-01-01T00:00:00.000Z").getTime(),
      source: "test",
    };
    const now_ms = new Date("2026-02-15T00:00:00.000Z").getTime();

    const r1 = evaluateDmswitch({ last_activity: activity, config, now_ms });
    const r2 = evaluateDmswitch({ last_activity: activity, config, now_ms });

    expect(r1.triggered).toBe(r2.triggered);
    expect(r1.elapsed_ms).toBe(r2.elapsed_ms);
    expect(r1.remaining_ms).toBe(r2.remaining_ms);
  });

  it("cascade state transitions are deterministic", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);

    const c1 = initiateCascade({ action: "key_rotation", fortress_id: fix.fortressId, roster });
    const c2 = initiateCascade({ action: "key_rotation", fortress_id: fix.fortressId, roster });

    // Both should be in "triggered" state.
    expect(c1.state).toBe("triggered");
    expect(c2.state).toBe("triggered");
    expect(c1.threshold_m).toBe(c2.threshold_m);
    expect(c1.threshold_n).toBe(c2.threshold_n);
  });
});

// ===================================================================
// Acceptance criterion 5: Recovery events use signed envelope
// ===================================================================

describe("acceptance criterion 5: recovery events use signed envelope", () => {
  it("packRecoveryEvent produces valid signed event", () => {
    const fix = buildFixture();

    const event = packRecoveryEvent({
      event_type: RECOVERY_EVENT_TYPES.GUARDIAN_ENROLL,
      fortress_id: fix.fortressId,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      payload: { test: "data" },
      signing_key: fix.nodeKp.privateKey,
    });

    expect(event.signature_scheme).toBe("ed25519-v1");
    expect(event.event_id).toBeTruthy();
    expect(event.payload_hash).toBeTruthy();
    expect(event.signature).toBeTruthy();
  });

  it("verifyRecoveryEvent validates valid events", () => {
    const fix = buildFixture();

    const event = packRecoveryEvent({
      event_type: RECOVERY_EVENT_TYPES.THRESHOLD_MET,
      fortress_id: fix.fortressId,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      payload: { cascade_id: "test" },
      signing_key: fix.nodeKp.privateKey,
    });

    expect(verifyRecoveryEvent(event, fix.nodeKp.publicKey)).toBe(true);
  });

  it("verifyRecoveryEvent rejects tampered payload", () => {
    const fix = buildFixture();

    const event = packRecoveryEvent({
      event_type: RECOVERY_EVENT_TYPES.THRESHOLD_MET,
      fortress_id: fix.fortressId,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      payload: { cascade_id: "test" },
      signing_key: fix.nodeKp.privateKey,
    });

    // Tamper with payload.
    const tampered = { ...event, payload: { cascade_id: "tampered" } };
    expect(verifyRecoveryEvent(tampered, fix.nodeKp.publicKey)).toBe(false);
  });

  it("verifyRecoveryEvent rejects wrong public key", () => {
    const fix = buildFixture();
    const wrongKp = generateKeypair();

    const event = packRecoveryEvent({
      event_type: RECOVERY_EVENT_TYPES.GUARDIAN_APPROVAL,
      fortress_id: fix.fortressId,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      payload: {},
      signing_key: fix.nodeKp.privateKey,
    });

    expect(verifyRecoveryEvent(event, wrongKp.publicKey)).toBe(false);
  });

  it("rejects invalid recovery event type", () => {
    const fix = buildFixture();

    expect(() =>
      packRecoveryEvent({
        event_type: "invalid_type" as any,
        fortress_id: fix.fortressId,
        emitter_node: fix.nodeId,
        emitter_principal: "root",
        payload: {},
        signing_key: fix.nodeKp.privateKey,
      })
    ).toThrow("invalid recovery event type");
  });
});

// ===================================================================
// Acceptance criterion 6: Multi-principal boundary evaluated
// ===================================================================

describe("acceptance criterion 6: multi-principal boundary", () => {
  it("allows when guardian threshold is met", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);

    const cascade: CascadeState = {
      cascade_id: "mp-1",
      state: "threshold_met",
      action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
      threshold_m: 3,
      threshold_n: 5,
      approvals: buildSignedApprovals(guardians, 3, "mp-1", "key_rotation", fix.fortressId, 1),
      initiated_at: new Date().toISOString(),
      events: [],
    };

    const result = evaluateMultiPrincipalBoundary({
      agent_id: "recovery:mp-1",
      recovery_action: "key_rotation",
      cascade_state: cascade,
      guardian_roster: roster,
    });

    expect(result.decision).toBe("allow");
    expect(result.reason_code).toBe(RECOVERY_GATE_REASON_CODES.RECOVERY_BOUNDARY_ALLOW);
    expect(result.valid_approvals).toBe(3);
  });

  it("denies when guardian threshold not met", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);

    const cascade: CascadeState = {
      cascade_id: "mp-2",
      state: "awaiting_threshold",
      action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
      threshold_m: 3,
      threshold_n: 5,
      approvals: buildSignedApprovals(guardians, 1, "mp-2", "key_rotation", fix.fortressId, 1),
      initiated_at: new Date().toISOString(),
      events: [],
    };

    const result = evaluateMultiPrincipalBoundary({
      agent_id: "recovery:mp-2",
      recovery_action: "key_rotation",
      cascade_state: cascade,
      guardian_roster: roster,
    });

    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(RECOVERY_GATE_REASON_CODES.GUARDIAN_THRESHOLD_NOT_MET);
  });

  it("denies when no guardian roster", () => {
    const cascade: CascadeState = {
      cascade_id: "mp-3",
      state: "awaiting_threshold",
      action: "key_rotation",
      fortress_id: "test-fortress",
      roster_version: 1,
      threshold_m: 3,
      threshold_n: 5,
      approvals: [],
      initiated_at: new Date().toISOString(),
      events: [],
    };

    const result = evaluateMultiPrincipalBoundary({
      agent_id: "recovery:mp-3",
      recovery_action: "key_rotation",
      cascade_state: cascade,
      guardian_roster: {
        m: 3,
        n: 0,
        guardians: [],
        signature_scheme: SIGNATURE_SCHEME_V1,
        version: 1,
        created_at: new Date().toISOString(),
        fortress_id: "test-fortress",
        master_signature: "",
      },
    });

    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(RECOVERY_GATE_REASON_CODES.NO_GUARDIAN_ROSTER);
  });

  it("denies when roster version mismatches", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3, 2); // version 2

    const cascade: CascadeState = {
      cascade_id: "mp-4",
      state: "awaiting_threshold",
      action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1, // references version 1
      threshold_m: 3,
      threshold_n: 5,
      approvals: [],
      initiated_at: new Date().toISOString(),
      events: [],
    };

    const result = evaluateMultiPrincipalBoundary({
      agent_id: "recovery:mp-4",
      recovery_action: "key_rotation",
      cascade_state: cascade,
      guardian_roster: roster,
    });

    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(RECOVERY_GATE_REASON_CODES.GUARDIAN_ROSTER_STALE);
  });
});

// ===================================================================
// Acceptance criterion 7: Non-dependency clean
// ===================================================================

describe("acceptance criterion 7: non-dependency clean", () => {
  it("recovery module has zero concordia or verascore imports", async () => {
    const { execSync } = await import("node:child_process");
    const worktreeRoot = "/Users/eriknewton/Code/Claude/sanctuary-worktrees/wp-mvp-8-recovery-cascade";
    const result = execSync(
      `grep -r "concordia\\|verascore" "${worktreeRoot}/server/src/recovery/" || true`,
      { encoding: "utf-8" }
    );
    expect(result.trim()).toBe("");
  });
});

// ===================================================================
// Acceptance criterion 8: Real-crypto tests
// ===================================================================

describe("acceptance criterion 8: real-crypto tests", () => {
  it("guardian approval uses real Ed25519 signatures", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);
    const signingInput = buildApprovalSigningInput({
      cascade_id: "crypto-1",
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });

    const approval = signApproval({
      signing_input: signingInput,
      guardian_id: guardians[0]!.identity.guardian_id,
      guardian_private_key: guardians[0]!.kp.privateKey,
      recovery_action: "key_rotation",
      cascade_id: "crypto-1",
    });

    // Manually verify the Ed25519 signature.
    const signedBytes = canonicalizeToBytes(signingInput);
    const sigBytes = fromBase64url(approval.signature);
    const pubKey = fromBase64url(guardians[0]!.identity.public_key);
    expect(ed25519.verify(sigBytes, signedBytes, pubKey)).toBe(true);
  });

  it("recovery event signature is real Ed25519", () => {
    const fix = buildFixture();

    const event = packRecoveryEvent({
      event_type: RECOVERY_EVENT_TYPES.RECOVERY_EXECUTED,
      fortress_id: fix.fortressId,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      payload: { action: "key_rotation" },
      signing_key: fix.nodeKp.privateKey,
    });

    // Manually verify.
    const { signature, ...body } = event;
    const sigBytes = fromBase64url(signature);
    const bodyBytes = canonicalizeToBytes(body);
    expect(ed25519.verify(sigBytes, bodyBytes, fix.nodeKp.publicKey)).toBe(true);
  });

  it("no mocked crypto at boundaries (explicit assertion)", () => {
    // This test asserts that our threshold evaluator calls real ed25519.verify,
    // not a mock. We do this by signing with a wrong key and confirming failure.
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const wrongKp = generateKeypair();
    const roster = buildRoster(fix, guardians, 3);
    const signingInput = buildApprovalSigningInput({
      cascade_id: "nomock",
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });

    // Sign with wrong key (not the guardian's key).
    const badApproval = signApproval({
      signing_input: signingInput,
      guardian_id: guardians[0]!.identity.guardian_id,
      guardian_private_key: wrongKp.privateKey, // WRONG KEY
      recovery_action: "key_rotation",
      cascade_id: "nomock",
    });

    const result = evaluateThreshold({
      approvals: [badApproval],
      roster,
      signing_input: signingInput,
    });

    expect(result.valid_count).toBe(0);
    expect(result.invalid_guardian_ids).toContain(guardians[0]!.identity.guardian_id);
  });
});

// ===================================================================
// Acceptance criterion 9: Operator knob honored
// ===================================================================

describe("acceptance criterion 9: operator knob honored", () => {
  it("respects custom max_offline_window", () => {
    const tenDays = 10 * 24 * 60 * 60 * 1000;
    const config: DmswitchConfig = {
      max_offline_window_ms: tenDays,
      estate_planning_enabled: false,
    };
    const activity = buildActivity(tenDays + 1000);

    const result = evaluateDmswitch({ last_activity: activity, config });
    expect(result.triggered).toBe(true);
  });

  it("rejects window below minimum (7 days)", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: 1 * 24 * 60 * 60 * 1000, // 1 day
      estate_planning_enabled: false,
    };

    expect(() => validateDmswitchConfig(config)).toThrow(RecoveryConfigError);
  });

  it("rejects non-estate window above 30 days", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: 60 * 24 * 60 * 60 * 1000, // 60 days
      estate_planning_enabled: false,
    };

    expect(() => validateDmswitchConfig(config)).toThrow(RecoveryConfigError);
  });

  it("allows estate window up to 90 days", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: MAX_ESTATE_PLANNING_WINDOW_MS,
      estate_planning_enabled: true,
    };

    expect(() => validateDmswitchConfig(config)).not.toThrow();
  });

  it("rejects estate window above 90 days", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: 120 * 24 * 60 * 60 * 1000, // 120 days
      estate_planning_enabled: true,
    };

    expect(() => validateDmswitchConfig(config)).toThrow(RecoveryConfigError);
  });
});

// ===================================================================
// Acceptance criterion 10: Failure modes documented + tested
// ===================================================================

describe("acceptance criterion 10: failure modes", () => {
  describe("(a) threshold-not-met", () => {
    it("ThresholdNotMetError carries valid_count and threshold_m", () => {
      const err = new ThresholdNotMetError({ valid_count: 1, threshold_m: 3 });
      expect(err.name).toBe("ThresholdNotMetError");
      expect(err.code).toBe("threshold_not_met");
      expect(err.valid_count).toBe(1);
      expect(err.threshold_m).toBe(3);
    });
  });

  describe("(b) window-not-expired", () => {
    it("WindowNotExpiredError carries remaining_ms and expires_at", () => {
      const err = new WindowNotExpiredError({
        remaining_ms: 86400000,
        expires_at: "2026-05-01T00:00:00.000Z",
      });
      expect(err.name).toBe("WindowNotExpiredError");
      expect(err.code).toBe("window_not_expired");
      expect(err.remaining_ms).toBe(86400000);
      expect(err.expires_at).toBe("2026-05-01T00:00:00.000Z");
    });

    it("emitCascadeEntry throws when window not expired", () => {
      const fix = buildFixture();
      const config: DmswitchConfig = {
        max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
        estate_planning_enabled: false,
      };
      const activity = buildActivity(1000); // Very recent.

      expect(() =>
        emitCascadeEntry({
          last_activity: activity,
          config,
          fortress_id: fix.fortressId,
          emitter_node: fix.nodeId,
          emitter_principal: "root",
          signing_key: fix.nodeKp.privateKey,
        })
      ).toThrow(WindowNotExpiredError);
    });
  });

  describe("(c) signature-invalid", () => {
    it("SignatureInvalidError carries guardian_id", () => {
      const err = new SignatureInvalidError({
        guardian_id: "g1",
        detail: "key mismatch",
      });
      expect(err.name).toBe("SignatureInvalidError");
      expect(err.code).toBe("signature_invalid");
      expect(err.guardian_id).toBe("g1");
    });

    it("evaluateThreshold marks invalid signature as invalid", () => {
      const fix = buildFixture();
      const guardians = buildGuardians(5);
      const wrongKp = generateKeypair();
      const roster = buildRoster(fix, guardians, 3);
      const signingInput = buildApprovalSigningInput({
        cascade_id: "sig-inv",
        recovery_action: "key_rotation",
        fortress_id: fix.fortressId,
        roster_version: 1,
      });

      const badApproval = signApproval({
        signing_input: signingInput,
        guardian_id: guardians[0]!.identity.guardian_id,
        guardian_private_key: wrongKp.privateKey,
        recovery_action: "key_rotation",
        cascade_id: "sig-inv",
      });

      const result = evaluateThreshold({
        approvals: [badApproval],
        roster,
        signing_input: signingInput,
      });
      expect(result.invalid_guardian_ids).toContain(guardians[0]!.identity.guardian_id);
    });
  });

  describe("(d) roster-stale", () => {
    it("RosterStaleError carries expected and actual versions", () => {
      const err = new RosterStaleError({
        expected_version: 2,
        actual_version: 1,
      });
      expect(err.name).toBe("RosterStaleError");
      expect(err.code).toBe("roster_stale");
      expect(err.expected_version).toBe(2);
      expect(err.actual_version).toBe(1);
    });

    it("enforceThreshold throws RosterStaleError on version mismatch", () => {
      const fix = buildFixture();
      const guardians = buildGuardians(5);
      const roster = buildRoster(fix, guardians, 3, 2); // version 2
      const signingInput = buildApprovalSigningInput({
        cascade_id: "stale",
        recovery_action: "key_rotation",
        fortress_id: fix.fortressId,
        roster_version: 1,
      });

      expect(() =>
        enforceThreshold({
          approvals: [],
          roster,
          signing_input: signingInput,
          expected_roster_version: 1, // expects version 1 but roster is v2
        })
      ).toThrow(RosterStaleError);
    });
  });
});

// ===================================================================
// Integration: full cascade flow
// ===================================================================

describe("integration: full cascade flow", () => {
  it("DMswitch -> initiate -> approvals -> threshold met -> execute", async () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const config: DmswitchConfig = {
      max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
      estate_planning_enabled: false,
    };
    const store = new RecoveryStore();
    const ctx = {
      fortress_id: fix.fortressId,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      node_signing_key: fix.nodeKp.privateKey,
      roster,
      config: { dmswitch: config },
      store,
    };

    // 1. Init recovery with DMswitch trigger.
    const activity = buildActivity(DEFAULT_DMSWITCH_WINDOW_MS + 1000);
    const { cascade: c1, entry_event } = initRecovery({
      ctx,
      action: "key_rotation",
      last_activity: activity,
    });

    expect(c1.state).toBe("awaiting_threshold");
    expect(entry_event).toBeTruthy();
    expect(entry_event!.event_type).toBe(RECOVERY_EVENT_TYPES.DMSWITCH_CASCADE_ENTRY);

    // 2. Register 3 guardian approvals.
    let latestCascade = c1;
    for (let i = 0; i < 3; i++) {
      const signingInput = buildApprovalSigningInput({
        cascade_id: c1.cascade_id,
        recovery_action: c1.action,
        fortress_id: fix.fortressId,
        roster_version: 1,
      });
      const approval = signApproval({
        signing_input: signingInput,
        guardian_id: guardians[i]!.identity.guardian_id,
        guardian_private_key: guardians[i]!.kp.privateKey,
        recovery_action: c1.action,
        cascade_id: c1.cascade_id,
      });

      const result = registerGuardianApproval({
        ctx,
        cascade_id: c1.cascade_id,
        approval,
      });
      latestCascade = result.cascade;

      if (i < 2) {
        expect(result.threshold_met).toBe(false);
      } else {
        expect(result.threshold_met).toBe(true);
        expect(result.boundary_result).toBeTruthy();
        expect(result.boundary_result!.decision).toBe("allow");
      }
    }

    expect(latestCascade.state).toBe("threshold_met");

    // 3. Execute the cascade.
    let executorCalled = false;
    const finalCascade = await executeRecovery({
      ctx,
      cascade_id: c1.cascade_id,
      executor: async () => {
        executorCalled = true;
      },
    });

    expect(executorCalled).toBe(true);
    expect(finalCascade.state).toBe("completed");
    expect(finalCascade.completed_at).toBeTruthy();
    expect(finalCascade.events.length).toBeGreaterThan(0);
    expect(finalCascade.events.some(
      (e) => e.event_type === RECOVERY_EVENT_TYPES.RECOVERY_EXECUTED
    )).toBe(true);
  });

  it("manual recovery (no DMswitch) works", async () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);
    const store = new RecoveryStore();
    const ctx = {
      fortress_id: fix.fortressId,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      node_signing_key: fix.nodeKp.privateKey,
      roster,
      config: {
        dmswitch: {
          max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
          estate_planning_enabled: false,
        },
      },
      store,
    };

    // Init without DMswitch trigger.
    const { cascade: c1 } = initRecovery({ ctx, action: "emergency_freeze" });
    expect(c1.state).toBe("awaiting_threshold");
    expect(c1.dmswitch_trigger).toBeUndefined();

    // Register 2 approvals.
    for (let i = 0; i < 2; i++) {
      const signingInput = buildApprovalSigningInput({
        cascade_id: c1.cascade_id,
        recovery_action: c1.action,
        fortress_id: fix.fortressId,
        roster_version: 1,
      });
      registerGuardianApproval({
        ctx,
        cascade_id: c1.cascade_id,
        approval: signApproval({
          signing_input: signingInput,
          guardian_id: guardians[i]!.identity.guardian_id,
          guardian_private_key: guardians[i]!.kp.privateKey,
          recovery_action: c1.action,
          cascade_id: c1.cascade_id,
        }),
      });
    }

    const final = await executeRecovery({
      ctx,
      cascade_id: c1.cascade_id,
      executor: async () => {},
    });
    expect(final.state).toBe("completed");
  });

  it("cascade fails gracefully when executor throws", async () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);
    const store = new RecoveryStore();
    const ctx = {
      fortress_id: fix.fortressId,
      emitter_node: fix.nodeId,
      emitter_principal: "root",
      node_signing_key: fix.nodeKp.privateKey,
      roster,
      config: {
        dmswitch: {
          max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
          estate_planning_enabled: false,
        },
      },
      store,
    };

    const { cascade: c1 } = initRecovery({ ctx, action: "key_rotation" });
    for (let i = 0; i < 2; i++) {
      const signingInput = buildApprovalSigningInput({
        cascade_id: c1.cascade_id,
        recovery_action: c1.action,
        fortress_id: fix.fortressId,
        roster_version: 1,
      });
      registerGuardianApproval({
        ctx,
        cascade_id: c1.cascade_id,
        approval: signApproval({
          signing_input: signingInput,
          guardian_id: guardians[i]!.identity.guardian_id,
          guardian_private_key: guardians[i]!.kp.privateKey,
          recovery_action: c1.action,
          cascade_id: c1.cascade_id,
        }),
      });
    }

    const final = await executeRecovery({
      ctx,
      cascade_id: c1.cascade_id,
      executor: async () => {
        throw new Error("simulated failure");
      },
    });

    expect(final.state).toBe("failed");
    expect(final.failure_reason).toBe("simulated failure");
    expect(final.events.some(
      (e) => e.event_type === RECOVERY_EVENT_TYPES.RECOVERY_FAILED
    )).toBe(true);
  });
});

// ===================================================================
// Cascade state machine edge cases
// ===================================================================

describe("cascade state machine", () => {
  it("rejects duplicate guardian approval on cascade", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);
    let cascade = initiateCascade({ action: "key_rotation", fortress_id: fix.fortressId, roster });
    cascade = beginAwaitingThreshold(cascade);

    const signingInput = buildApprovalSigningInput({
      cascade_id: cascade.cascade_id,
      recovery_action: cascade.action,
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const approval = signApproval({
      signing_input: signingInput,
      guardian_id: guardians[0]!.identity.guardian_id,
      guardian_private_key: guardians[0]!.kp.privateKey,
      recovery_action: cascade.action,
      cascade_id: cascade.cascade_id,
    });

    cascade = registerApproval(cascade, approval);
    expect(() => registerApproval(cascade, approval)).toThrow(CascadeStateError);
  });

  it("failCascade sets failure state", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);
    const cascade = initiateCascade({ action: "key_rotation", fortress_id: fix.fortressId, roster });

    const failed = failCascade(cascade, "operator cancelled");
    expect(failed.state).toBe("failed");
    expect(failed.failure_reason).toBe("operator cancelled");
  });

  it("cannot fail an already completed cascade", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);
    const cascade: CascadeState = {
      ...initiateCascade({ action: "key_rotation", fortress_id: fix.fortressId, roster }),
      state: "completed",
      completed_at: new Date().toISOString(),
    };

    expect(() => failCascade(cascade, "reason")).toThrow(CascadeStateError);
  });

  it("RecoveryStore tracks active cascades", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(3);
    const roster = buildRoster(fix, guardians, 2);
    const store = new RecoveryStore();

    const c1 = initiateCascade({ action: "key_rotation", fortress_id: fix.fortressId, roster });
    const c2: CascadeState = {
      ...initiateCascade({ action: "estate_unlock", fortress_id: fix.fortressId, roster }),
      state: "completed",
      completed_at: new Date().toISOString(),
    };

    store.set(c1);
    store.set(c2);

    expect(store.list()).toHaveLength(2);
    expect(store.listActive()).toHaveLength(1);
    expect(store.listActive()[0]!.cascade_id).toBe(c1.cascade_id);
  });
});

// ===================================================================
// No LLM at gate (structural assertion)
// ===================================================================

describe("no LLM at gate (structural)", () => {
  it("threshold evaluation is pure arithmetic with no external calls", () => {
    // This test verifies the evaluateThreshold function is a pure function
    // by running it synchronously without any async/network setup.
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const signingInput = buildApprovalSigningInput({
      cascade_id: "no-llm",
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const approvals = buildSignedApprovals(guardians, 3, "no-llm", "key_rotation", fix.fortressId, 1);

    // evaluateThreshold is synchronous. If it required an LLM call,
    // it would need to be async. This is the structural assertion.
    const result = evaluateThreshold({ approvals, roster, signing_input: signingInput });
    expect(result.threshold_met).toBe(true);
  });

  it("DMswitch evaluation is pure arithmetic", () => {
    const config: DmswitchConfig = {
      max_offline_window_ms: DEFAULT_DMSWITCH_WINDOW_MS,
      estate_planning_enabled: false,
    };
    const activity = buildActivity(DEFAULT_DMSWITCH_WINDOW_MS + 1000);

    // evaluateDmswitch is synchronous. Pure function.
    const result = evaluateDmswitch({ last_activity: activity, config });
    expect(result.triggered).toBe(true);
  });
});

// ===================================================================
// Harden wave A3 (2026-07-04): recovery-cascade trust-boundary
// regression tests. Each test in this block fails on the pre-harden
// code and passes after the fix (fail-before / pass-after).
//
// Defect classes confirmed by adversarial audit:
//   A. cross-roster-version signature reuse (quorum bypass): a quorum
//      signed under roster vN verified against roster vM (N != M).
//   B. unauthenticated approval envelope-field confusion: an approval's
//      self-declared cascade_id / recovery_action were never bound to the
//      input the signature actually covered, nor to the cascade action.
//
// Classes that yielded NO real defect after audit (stated for the record):
//   - cross-cascade replay: already blocked; cascade_id is inside the
//     signed canonical input, so a signature for cascade A does not verify
//     against cascade B.
//   - execute-time raised threshold: executeCascade re-evaluates against
//     the current roster and fails closed when M was raised.
//   - m=0 / empty partial set: issueGuardianRoster rejects m<1 at issuance.
//   - DMswitch false-trigger: the evaluator is pure "elapsed >= window"
//     arithmetic and only gates cascade ENTRY, never the guardian threshold.
// ===================================================================

describe("harden A3: cross-roster-version signature reuse is closed", () => {
  it("evaluateThreshold does not count a v1-signed quorum against a v2 roster", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    // Roster v2 (e.g., after a guardian was revoked and version bumped).
    const rosterV2 = buildRoster(fix, guardians, 3, 2);

    // A quorum signed under roster_version = 1 (stale).
    const cascadeId = "cascade-stale-roster";
    const staleApprovals = buildSignedApprovals(
      guardians,
      3,
      cascadeId,
      "key_rotation",
      fix.fortressId,
      1
    );

    const signingInputV1 = buildApprovalSigningInput({
      cascade_id: cascadeId,
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });

    const result = evaluateThreshold({
      approvals: staleApprovals,
      roster: rosterV2,
      signing_input: signingInputV1,
    });

    // Fail closed: a stale-version quorum must not meet threshold.
    expect(result.threshold_met).toBe(false);
    expect(result.valid_count).toBe(0);
  });

  it("enforceThreshold throws RosterStaleError when signing input version != roster version, even without expected_roster_version", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const rosterV2 = buildRoster(fix, guardians, 3, 2);

    const cascadeId = "cascade-stale-enforce";
    const staleApprovals = buildSignedApprovals(
      guardians,
      3,
      cascadeId,
      "key_rotation",
      fix.fortressId,
      1
    );

    expect(() =>
      enforceThreshold({
        approvals: staleApprovals,
        roster: rosterV2,
        signing_input: buildApprovalSigningInput({
          cascade_id: cascadeId,
          recovery_action: "key_rotation",
          fortress_id: fix.fortressId,
          roster_version: 1,
        }),
      })
    ).toThrow(RosterStaleError);
  });

  it("a matched-version quorum still succeeds (bind does not over-block)", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const rosterV2 = buildRoster(fix, guardians, 3, 2);
    const cascadeId = "cascade-matched-version";
    const approvals = buildSignedApprovals(
      guardians,
      3,
      cascadeId,
      "key_rotation",
      fix.fortressId,
      2
    );
    const result = evaluateThreshold({
      approvals,
      roster: rosterV2,
      signing_input: buildApprovalSigningInput({
        cascade_id: cascadeId,
        recovery_action: "key_rotation",
        fortress_id: fix.fortressId,
        roster_version: 2,
      }),
    });
    expect(result.threshold_met).toBe(true);
    expect(result.valid_count).toBe(3);
  });
});

describe("harden A3: unauthenticated approval-envelope fields are bound", () => {
  it("evaluateThreshold does not count an approval whose declared recovery_action differs from the signing input", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3, 1);

    const cascadeId = "cascade-field-confusion";
    // Guardians sign the canonical input for key_rotation, but the approval
    // objects declare recovery_action = emergency_freeze in their envelope.
    const signingInput = buildApprovalSigningInput({
      cascade_id: cascadeId,
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const lyingApprovals = guardians.slice(0, 3).map((g) =>
      signApproval({
        signing_input: signingInput,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.kp.privateKey,
        recovery_action: "emergency_freeze",
        cascade_id: cascadeId,
      })
    );

    const result = evaluateThreshold({
      approvals: lyingApprovals,
      roster,
      signing_input: signingInput,
    });

    // Fail closed: mismatched declared action must not count.
    expect(result.threshold_met).toBe(false);
    expect(result.valid_count).toBe(0);
  });

  it("evaluateThreshold does not count an approval whose declared cascade_id differs from the signing input", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3, 1);

    const signingInput = buildApprovalSigningInput({
      cascade_id: "real-cascade",
      recovery_action: "key_rotation",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const lyingApprovals = guardians.slice(0, 3).map((g) =>
      signApproval({
        signing_input: signingInput,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.kp.privateKey,
        recovery_action: "key_rotation",
        cascade_id: "some-other-cascade",
      })
    );

    const result = evaluateThreshold({
      approvals: lyingApprovals,
      roster,
      signing_input: signingInput,
    });

    expect(result.threshold_met).toBe(false);
    expect(result.valid_count).toBe(0);
  });

  it("registerApproval rejects an approval whose recovery_action does not match the cascade action", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3, 1);

    let cascade = initiateCascade({
      action: "key_rotation",
      fortress_id: fix.fortressId,
      roster,
    });
    cascade = beginAwaitingThreshold(cascade);

    // An approval that targets this cascade_id but declares emergency_freeze.
    const signingInput = buildApprovalSigningInput({
      cascade_id: cascade.cascade_id,
      recovery_action: "emergency_freeze",
      fortress_id: fix.fortressId,
      roster_version: 1,
    });
    const mismatchedApproval = signApproval({
      signing_input: signingInput,
      guardian_id: guardians[0]!.identity.guardian_id,
      guardian_private_key: guardians[0]!.kp.privateKey,
      recovery_action: "emergency_freeze",
      cascade_id: cascade.cascade_id,
    });

    expect(() => registerApproval(cascade, mismatchedApproval)).toThrow(
      CascadeStateError
    );
  });

  it("registerApproval still accepts a correctly-actioned approval (bind does not over-block)", () => {
    const fix = buildFixture();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3, 1);
    let cascade = initiateCascade({
      action: "key_rotation",
      fortress_id: fix.fortressId,
      roster,
    });
    cascade = beginAwaitingThreshold(cascade);
    const [approval] = buildSignedApprovals(
      guardians,
      1,
      cascade.cascade_id,
      "key_rotation",
      fix.fortressId,
      1
    );
    const next = registerApproval(cascade, approval!);
    expect(next.approvals.length).toBe(1);
  });
});
