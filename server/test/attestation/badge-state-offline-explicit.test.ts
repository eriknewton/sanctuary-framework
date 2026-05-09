/**
 * Regression-prevention test for full-sweep #71:
 * deriveActionBadge() must return 'offline' for time_of_action_state === 'offline'.
 *
 * NOTE: This test passes both before and after the fix (the implicit fallthrough
 * at the end of deriveActionBadge already returned 'offline' via ctx.time_of_action_state).
 * The fix adds an explicit branch; this test prevents future refactors from breaking it.
 */

import { describe, it, expect } from "vitest";
import { deriveActionBadge } from "../../src/attestation/badge-state.js";
import type { ActionLayerContext } from "../../src/attestation/types.js";

describe("deriveActionBadge offline explicit branch (#71)", () => {
  it("returns 'offline' when time_of_action_state is 'offline'", () => {
    const ctx: ActionLayerContext = {
      action_id: "action-1",
      agent_id: "agent-1",
      fortress_id: "fortress-1",
      time_of_action_state: "offline",
      current_verifier_state: "green",
      policy_version: 1,
      action_at: new Date().toISOString(),
    };

    expect(deriveActionBadge(ctx)).toBe("offline");
  });

  it("returns 'offline' regardless of current_verifier_state", () => {
    const ctx: ActionLayerContext = {
      action_id: "action-2",
      agent_id: "agent-1",
      fortress_id: "fortress-1",
      time_of_action_state: "offline",
      current_verifier_state: "red",
      policy_version: 1,
      action_at: new Date().toISOString(),
    };

    expect(deriveActionBadge(ctx)).toBe("offline");
  });
});
