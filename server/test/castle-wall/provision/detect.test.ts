/**
 * Tests for shared-account detection (fix H3): config-first, ruid-vs-console
 * secondary, provision-by-default fallback.
 */

import { describe, it, expect } from "vitest";

import { detectProvisionNeed } from "../../../src/castle-wall/provision/detect.js";

const CEILING = 500;
const CONSOLE_OWNER = 501;

describe("castle-wall/provision/detect", () => {
  it("fix F6: skips provisioning ONLY when the harness config uid clears the ceiling test AND the account shape is VERIFIED", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: 502,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
      accountShapeVerdict: "verified-dedicated",
    });
    expect(result.needsProvisioning).toBe(false);
    expect(result.alreadyDedicated).toBe(true);
    expect(result.resolved).toEqual({ uid: 502, source: "harness-config" });
  });

  it("fix F6 (Codex second family): a stale/foreign uid that clears the ceiling test but is NOT the verified dedicated account PROVISIONS (does not skip)", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: 502,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
      accountShapeVerdict: "not-dedicated",
    });
    expect(result.needsProvisioning).toBe(true);
    expect(result.alreadyDedicated).toBe(false);
  });

  it("fix F6: an indeterminate account-shape verdict (probe failed/ambiguous) fails CLOSED -- provisions rather than trusting an unverified uid", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: 502,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
      accountShapeVerdict: "indeterminate",
    });
    expect(result.needsProvisioning).toBe(true);
    expect(result.alreadyDedicated).toBe(false);
  });

  it("fix F6: omitting accountShapeVerdict entirely (caller did not probe) also fails CLOSED -- provisions", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: 502,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
    });
    expect(result.needsProvisioning).toBe(true);
    expect(result.alreadyDedicated).toBe(false);
  });

  it("fix F6: a stale/foreign RUNNING-PROCESS uid that clears the ceiling test but is not verified PROVISIONS (does not skip)", () => {
    const result = detectProvisionNeed({
      runningAgentUid: 503,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
      accountShapeVerdict: "not-dedicated",
    });
    expect(result.needsProvisioning).toBe(true);
    expect(result.alreadyDedicated).toBe(false);
  });

  it("fix F6: the genuine dedicated account (verified shape) via the running-process signal skips (still reaches arm at the orchestrator)", () => {
    const result = detectProvisionNeed({
      runningAgentUid: 503,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
      accountShapeVerdict: "verified-dedicated",
    });
    expect(result.needsProvisioning).toBe(false);
    expect(result.alreadyDedicated).toBe(true);
  });

  it("provisions when the harness config uid matches the console owner (shared account)", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: CONSOLE_OWNER,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
    });
    expect(result.needsProvisioning).toBe(true);
    expect(result.alreadyDedicated).toBe(false);
  });

  it("provisions when the harness config uid is below the ceiling", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: 10,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
    });
    expect(result.needsProvisioning).toBe(true);
    expect(result.alreadyDedicated).toBe(false);
  });

  it("falls back to the running-process ruid when no harness config uid is known (verified shape)", () => {
    const result = detectProvisionNeed({
      runningAgentUid: 503,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
      accountShapeVerdict: "verified-dedicated",
    });
    expect(result.needsProvisioning).toBe(false);
    expect(result.alreadyDedicated).toBe(true);
    expect(result.resolved).toEqual({ uid: 503, source: "running-process" });
  });

  it("treats a running agent at the console owner's uid as shared, not dedicated", () => {
    const result = detectProvisionNeed({
      runningAgentUid: CONSOLE_OWNER,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
    });
    expect(result.needsProvisioning).toBe(true);
    expect(result.alreadyDedicated).toBe(false);
  });

  it("H3: provisions by default when neither signal resolves (fail-closed, not fail-open)", () => {
    const result = detectProvisionNeed({
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
    });
    expect(result.needsProvisioning).toBe(true);
    expect(result.alreadyDedicated).toBe(false);
    expect(result.resolved).toBeUndefined();
    expect(result.reason).toMatch(/provisioning by default/);
  });

  it("prefers the harness-config signal over a running-process signal when both are present (verified shape)", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: 502,
      runningAgentUid: CONSOLE_OWNER,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
      accountShapeVerdict: "verified-dedicated",
    });
    expect(result.resolved?.source).toBe("harness-config");
    expect(result.alreadyDedicated).toBe(true);
  });

  it("boundary: a uid exactly equal to the ceiling counts as dedicated when distinct from console owner AND verified", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: CEILING,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
      accountShapeVerdict: "verified-dedicated",
    });
    expect(result.alreadyDedicated).toBe(true);
  });

  it("boundary: a uid exactly equal to the ceiling WITHOUT a verified shape does not count as dedicated (fix F6)", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: CEILING,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
    });
    expect(result.alreadyDedicated).toBe(false);
    expect(result.needsProvisioning).toBe(true);
  });
});
