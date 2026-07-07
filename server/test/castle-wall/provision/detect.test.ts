/**
 * Tests for shared-account detection (fix H3): config-first, ruid-vs-console
 * secondary, provision-by-default fallback.
 */

import { describe, it, expect } from "vitest";

import { detectProvisionNeed } from "../../../src/castle-wall/provision/detect.js";

const CEILING = 500;
const CONSOLE_OWNER = 501;

describe("castle-wall/provision/detect", () => {
  it("skips provisioning when the harness config already declares a dedicated uid", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: 502,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
    });
    expect(result.needsProvisioning).toBe(false);
    expect(result.alreadyDedicated).toBe(true);
    expect(result.resolved).toEqual({ uid: 502, source: "harness-config" });
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

  it("falls back to the running-process ruid when no harness config uid is known", () => {
    const result = detectProvisionNeed({
      runningAgentUid: 503,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
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

  it("prefers the harness-config signal over a running-process signal when both are present", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: 502,
      runningAgentUid: CONSOLE_OWNER,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
    });
    expect(result.resolved?.source).toBe("harness-config");
    expect(result.alreadyDedicated).toBe(true);
  });

  it("boundary: a uid exactly equal to the ceiling counts as dedicated (when distinct from console owner)", () => {
    const result = detectProvisionNeed({
      harnessConfiguredUid: CEILING,
      consoleOwnerUid: CONSOLE_OWNER,
      ceiling: CEILING,
    });
    expect(result.alreadyDedicated).toBe(true);
  });
});
