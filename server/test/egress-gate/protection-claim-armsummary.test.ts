/**
 * F-ARMSUMMARY (MEDIUM, 2026-07-26 Mini1 drill): ONE successful arm printed
 * three mutually inconsistent statements about the same wall, in one run, in
 * this order (`L1-arm-exclusive.log`):
 *
 *   line 16  "WARNING: Castle Wall is NOT armed ... outbound traffic is NOT
 *             filtered. Reason: A Castle Wall SAFE-MODE boot daemon (PID 1432)
 *             is currently enforcing this fortress."
 *   line 65  "Dedicated agent account provisioned, Castle Wall armed, and the
 *             exclusive-egress gate is LIVE (uid 503, generation 24)."
 *   line 75  "Castle Wall status unknown (not confirmed armed)"
 *
 * Independent measurement at that moment said ARMED (sysext activated, content
 * filter enabled, lease armed, the confined uid measurably confined). The
 * direction was safe, but an operator reading that output cannot tell whether
 * they are protected, and line 75 is the sentence a published artifact would
 * quote.
 *
 * Both halves of the fix live in the protection-copy chokepoint, so there is
 * one wording path rather than three positions in the control flow each
 * describing the wall in its own vocabulary.
 */

import { describe, it, expect } from "vitest";

import {
  castleWallDaemonStartFailureHeadline,
  protectionStateAdvice,
  protectionStateClaimFromObservation,
  reconcileProtectionClaimWithArmOutcome,
  type ProtectionStateClaim,
} from "../../src/egress-gate/protection-claim.js";

/** The literal reason the drill's daemon start failed on. */
const SAFE_MODE_HELD =
  "A Castle Wall SAFE-MODE boot daemon (PID 1432) is currently enforcing this fortress.";

const unknownClaim = (
  basis: "insufficient_evidence" | "provider_unavailable" | "read_failed",
): ProtectionStateClaim =>
  protectionStateClaimFromObservation({
    state: "unknown",
    basis,
    reasons: ["Castle Wall enforcement could not be observed"],
  });

describe("F-ARMSUMMARY line 16: the daemon-start warning does not claim what it never looked at", () => {
  it("does NOT say the wall is not armed when the start failed BECAUSE another daemon is enforcing", () => {
    const headline = castleWallDaemonStartFailureHeadline(SAFE_MODE_HELD).join("\n");
    // The exact contradiction the drill captured.
    expect(headline).not.toMatch(/Castle Wall is NOT armed/i);
    expect(headline).not.toMatch(/NOT filtered/i);
    // And it says the true thing instead.
    expect(headline).toMatch(/another one\s+already holds this fortress/i);
    expect(headline).toMatch(/neither armed nor disarmed anything/i);
  });

  it("is still loud for an ordinary start failure, but claims only what this run did", () => {
    const headline = castleWallDaemonStartFailureHeadline(
      "helper signing is unavailable: no reachable signer",
    ).join("\n");
    expect(headline).toMatch(/WARNING/);
    expect(headline).toMatch(/this run did not start the Castle Wall enforcement daemon/i);
    // It does NOT assert the host's filtering state -- it never observed it.
    expect(headline).not.toMatch(/traffic is NOT filtered/i);
    expect(headline).toMatch(/was NOT checked here/i);
  });

  it.each([
    "Castle Wall daemon is already running for this fortress",
    "refusing to start: a boot daemon is already enforcing this fortress",
    "the fortress is already armed by another daemon",
  ])("treats %j as already-held, not as not-armed", (message) => {
    const headline = castleWallDaemonStartFailureHeadline(message).join("\n");
    expect(headline).toMatch(/already holds this fortress/i);
  });
});

describe("F-ARMSUMMARY line 75: the closing summary is reconciled with what the run did", () => {
  it("qualifies a generic unknown when this run's arm step reported success", () => {
    const reconciled = reconcileProtectionClaimWithArmOutcome(
      unknownClaim("insufficient_evidence"),
      true,
    );
    expect(reconciled.basis).toBe("armed_this_run_enforcement_unobserved");
    const advice = protectionStateAdvice(reconciled);
    // The verdict is UNCHANGED: never green, same imperative class.
    expect(advice.green).toBe(false);
    expect(advice.castleWallLabel).toContain("Castle Wall status unknown");
    // The contradiction is gone.
    expect(advice.castleWallLabel).not.toContain("(not confirmed armed)");
    expect(advice.operatorSentence).toContain("arm step reported success");
    expect(advice.operatorSentence).toContain("not confirmed");
  });

  it("carries the probed reasons through unchanged (evidence is never dropped for wording)", () => {
    const original = unknownClaim("provider_unavailable");
    const reconciled = reconcileProtectionClaimWithArmOutcome(original, true);
    expect(reconciled.reasons).toEqual(original.reasons);
  });

  it("changes NOTHING when the run's arm step did not report success", () => {
    for (const basis of ["insufficient_evidence", "provider_unavailable", "read_failed"] as const) {
      const original = unknownClaim(basis);
      expect(reconcileProtectionClaimWithArmOutcome(original, false)).toBe(original);
    }
  });

  it("never upgrades a non-unknown state (an arm outcome cannot make protection green)", () => {
    const unprotected = protectionStateClaimFromObservation({
      state: "unprotected",
      basis: "disarm_observed_off",
      reasons: ["disarm observed"],
    });
    const coarse = protectionStateClaimFromObservation({
      state: "coarse-only",
      basis: "exclusive_egress_cap_observed",
      reasons: [],
    });
    expect(reconcileProtectionClaimWithArmOutcome(unprotected, true)).toBe(unprotected);
    expect(reconcileProtectionClaimWithArmOutcome(coarse, true)).toBe(coarse);
    expect(protectionStateAdvice(reconcileProtectionClaimWithArmOutcome(unprotected, true)).green).toBe(
      false,
    );
  });

  it("leaves a SPECIFIC unknown basis alone (its wording already names what is missing)", () => {
    for (const basis of [
      "daemon_liveness_missing",
      "subject_unbound_evidence",
      "exclusive_egress_repark_failed",
      "subject_unresolvable",
      "legacy_macos_audit_token",
      "pre_canonical_linux_agent_name",
    ] as const) {
      const original = protectionStateClaimFromObservation({
        state: "unknown",
        basis,
        reasons: ["r"],
      });
      expect(
        reconcileProtectionClaimWithArmOutcome(original, true),
        `${basis} must keep its specific wording`,
      ).toBe(original);
    }
  });
});
