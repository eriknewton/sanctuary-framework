/**
 * Dashboard copy sweep — Tier 4 Batch 4 PR 1 regression tests.
 *
 * Asserts the 8 sub-fixes (JJJJ, LLLL, IIII, FFFF, VVVVV, MMMM, HHHH, YYYY)
 * are present in the client script and HTML shell.
 */

import { describe, it, expect } from "vitest";
import { getClientScript } from "../../src/dashboard/v1_1/client.js";
import { renderDashboardV11Html } from "../../src/dashboard/v1_1/html.js";

const script = getClientScript();

describe("Dashboard copy sweep — Tier 4", () => {
  // JJJJ: Policy tab no longer shows stale "v1.1" badge
  it("JJJJ: policy heading does not contain v1.1 badge", () => {
    expect(script).not.toContain('pill tone-verified">v1.1</span>');
    expect(script).toContain("One screen for every rule</h1>");
  });

  // LLLL: Health tab no longer says "lands in v1.2"
  it("LLLL: health subtitle does not reference v1.2", () => {
    expect(script).not.toContain("lands in v1.2");
    expect(script).toContain("Projected from existing data.</p>");
  });

  // IIII: Honeypots tab shows create CTA in empty state
  it("IIII: honeypot page includes v1.4 create CTA for empty state", () => {
    expect(script).toContain("Coming in v1.4: full create UI");
    expect(script).toContain("sanctuary auto-trigger promote");
  });

  // FFFF: Auto-trigger empty state says "No auto-trigger ladders configured"
  it("FFFF: auto-trigger empty state names the condition", () => {
    expect(script).toContain("No auto-trigger ladders configured");
    expect(script).toContain("sanctuary auto-trigger promote");
  });

  // VVVVV: Approvals inbox has tier grouping headers
  it("VVVVV: inbox renders tier grouping headers", () => {
    expect(script).toContain("inbox-group-head");
    expect(script).toContain("Tier 1 approvals");
    expect(script).toContain("Tier 2 approvals");
  });

  // MMMM: Privacy and Coordination empty states have explanatory copy
  it("MMMM: privacy empty state explains what populates the tab", () => {
    expect(script).toContain("No privacy events recorded yet.");
    expect(script).toContain("privacy filter redacts");
  });

  it("MMMM: coordination empty state explains what populates the tab", () => {
    expect(script).toContain("No coordination flows recorded yet.");
    expect(script).toContain("protected agents hand off tasks");
  });

  // HHHH: Template count is dynamic, not hardcoded "6"
  it("HHHH: template count uses CHANNEL_TEMPLATES.length, not hardcoded 6", () => {
    expect(script).not.toContain("Channel templates · 6 shipped");
    expect(script).toContain("CHANNEL_TEMPLATES.length");
  });

  // YYYY: "Run full audit" button is not disabled
  it("YYYY: run full audit button is enabled with data-action", () => {
    expect(script).toContain('data-action="run-full-audit"');
    expect(script).not.toContain('disabled title="Manual audit landing in v1.2."');
  });

  // YYYY: onRunFullAudit handler exists
  it("YYYY: onRunFullAudit handler is defined", () => {
    expect(script).toContain("async function onRunFullAudit()");
    expect(script).toContain("/audit-chain/verify");
  });

  // VVVVV: CSS for inbox group heads exists in HTML shell
  it("VVVVV: inbox-group-head CSS exists in HTML shell", () => {
    const html = renderDashboardV11Html({ sanctuaryVersion: "1.3.0-test", embedClient: false });
    expect(html).toContain(".inbox-group-head");
  });
});
