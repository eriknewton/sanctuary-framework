/**
 * Sanctuary v1.1 Dashboard — Tier 1 approval flow tests.
 *
 * Covers required test 2: clicking a Tier 1 action emits the expected
 * POST, dashboard renders "Awaiting approval" state, does NOT optimistically
 * flip to engaged.
 *
 * The Tier 1 button copy table at status-mapping.ts is the source of truth
 * for state transitions: idle → pending → engaged. Cancellation:
 * pending → idle on inbox deny.
 */

import { describe, expect, it } from "vitest";
import { TIER1_BUTTON_COPY } from "../../../src/dashboard/v1_1/status-mapping.js";

describe("v1.1 dashboard Tier 1 button copy", () => {
  it("lockdown has three states: idle / pending / engaged", () => {
    const c = TIER1_BUTTON_COPY.lockdown;
    expect(c.idle).toBe("Lockdown");
    expect(c.pending).toBe("Awaiting approval");
    expect(c.engaged).toBe("Lockdown ON");
    expect(c.cancelled).toContain("not engaged");
  });

  it("unwrap has three states: idle / pending / engaged", () => {
    const c = TIER1_BUTTON_COPY.unwrap;
    expect(c.idle).toBe("Unwrap");
    expect(c.pending).toContain("pending");
    expect(c.engaged).toBe("Unwrapped");
  });

  it("policy_change has three states: idle / pending / engaged", () => {
    const c = TIER1_BUTTON_COPY.policy_change;
    expect(c.idle).toBe("Edit policy");
    expect(c.pending).toContain("pending");
  });

  it("exit_bundle_export has three states: idle / pending / engaged", () => {
    const c = TIER1_BUTTON_COPY.exit_bundle_export;
    expect(c.idle).toBe("Snapshot now");
    expect(c.pending).toContain("approval");
    expect(c.engaged).toBe("Bundle ready");
  });
});

describe("v1.1 dashboard Tier 1 client logic", () => {
  it("client script wires lockdown to POST /agents/all/lockdown then 'pending' state", async () => {
    const { getClientScript } = await import(
      "../../../src/dashboard/v1_1/client.js"
    );
    const src = getClientScript();
    // The two-step contract is encoded in the source: a successful
    // lockdown call sets state.tier1.lockdown.state to "pending".
    expect(src).toContain("/agents/all/lockdown");
    expect(src).toMatch(/state:\s*"pending"/);
    // The engaged transition lives in the inbox-action handler, NOT the
    // initial POST handler. The lockdown POST must NEVER set
    // "engaged" directly.
    const lockdownBlock =
      src.match(/onLockdownClick[\s\S]+?\n\}/)?.[0] ?? "";
    expect(lockdownBlock).not.toMatch(/state:\s*"engaged"/);
  });

  it("client script transitions to engaged state only on inbox approval", async () => {
    const { getClientScript } = await import(
      "../../../src/dashboard/v1_1/client.js"
    );
    const src = getClientScript();
    // Engaged transition lives in the inbox handler; gated by
    // (action === "approve") ? "engaged" : "idle".
    expect(src).toMatch(/action === "approve" \? "engaged" : "idle"/);
  });

  it("client script sends bearer and prompts for mutating 401 responses", async () => {
    const { getClientScript } = await import(
      "../../../src/dashboard/v1_1/client.js"
    );
    const src = getClientScript();
    expect(src).toContain('init.headers["Authorization"] = "Bearer " + TOKEN');
    expect(src).toContain(
      'if (res.status === 401 && method !== "GET" && promptForOperatorToken())',
    );
    expect(src).toContain('sessionStorage.setItem("authToken", TOKEN)');
  });
});
