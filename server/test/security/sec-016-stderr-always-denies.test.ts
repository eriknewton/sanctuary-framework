/**
 * Sanctuary MCP Server — SEC-016 Regression Test
 *
 * SEC-016: Stderr approval channel auto-resolves in 100ms.
 *
 * This test verifies that the stderr channel:
 * 1. Always denies (no configuration can change this)
 * 2. Denies immediately with no async delay (no 100ms timing window)
 * 3. Reports decided_by as "stderr:non-interactive" (not "timeout")
 * 4. Ignores auto_deny config (SEC-002 interaction)
 *
 * These tests would have exhibited the 100ms timing window before the
 * SEC-016 fix was applied.
 */

import { describe, it, expect } from "vitest";
import { StderrApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type { ApprovalRequest } from "../../src/principal-policy/types.js";

const TIER_1_REQUEST: ApprovalRequest = {
  operation: "state_export",
  tier: 1,
  reason: "SEC-016 regression test — Tier 1",
  context: { namespace: "test" },
  timestamp: new Date().toISOString(),
};

const TIER_2_REQUEST: ApprovalRequest = {
  operation: "state_read",
  tier: 2,
  reason: "SEC-016 regression test — Tier 2 anomaly",
  context: { namespace: "test", anomaly: "frequency_spike" },
  timestamp: new Date().toISOString(),
};

describe("SEC-016: Stderr channel always denies with no timing window", () => {

  it("always denies Tier 1 operations with decided_by stderr:non-interactive", async () => {
    const channel = new StderrApprovalChannel({
      type: "stderr",
      timeout_seconds: 30,
    });

    const response = await channel.requestApproval(TIER_1_REQUEST);

    expect(response.decision).toBe("deny");
    expect(response.decided_by).toBe("stderr:non-interactive");
    expect(response.decided_at).toBeTruthy();
  });

  it("denies immediately with no timing window (< 10ms, not 100ms)", async () => {
    const channel = new StderrApprovalChannel({
      type: "stderr",
      timeout_seconds: 30,
    });

    const start = performance.now();
    const response = await channel.requestApproval(TIER_1_REQUEST);
    const elapsed = performance.now() - start;

    expect(response.decision).toBe("deny");
    // Must complete in under 10ms — the old 100ms setTimeout is gone
    expect(elapsed).toBeLessThan(10);
  });

  it("ignores auto_deny: false config (SEC-002 interaction)", async () => {
    // SEC-002 removed the ability for auto_deny: false to cause auto-approve.
    // SEC-016 goes further: there is no timeout at all, so auto_deny is moot.
    const channel = new StderrApprovalChannel({
      type: "stderr",
      timeout_seconds: 30,
      auto_deny: false, // Must be ignored
    });

    const response = await channel.requestApproval(TIER_1_REQUEST);

    expect(response.decision).toBe("deny");
    expect(response.decided_by).toBe("stderr:non-interactive");
  });

  it("denies Tier 2 operations identically", async () => {
    const channel = new StderrApprovalChannel({
      type: "stderr",
      timeout_seconds: 30,
    });

    const response = await channel.requestApproval(TIER_2_REQUEST);

    expect(response.decision).toBe("deny");
    expect(response.decided_by).toBe("stderr:non-interactive");
    expect(response.decided_at).toBeTruthy();
  });
});
