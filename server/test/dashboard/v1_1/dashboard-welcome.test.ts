/**
 * Sanctuary v1.1 Dashboard — Welcome card (v1.1.7 Finding EE)
 *
 * v1.1.6 shipped a half-built chat surface on the Dashboard view: an
 * empty thread with a `Suggestion to concierge. (Direct commands land
 * in v1.2.)` text input. Operators couldn't tell whether the page was
 * broken or stub-on-purpose.
 *
 * v1.1.7 fix: replaces the chat surface with a static "What you can do
 * today" summary card mapping each nav target to the operator action it
 * enables. The chat affordance is gone entirely; operator chat ships in
 * v1.2 (WP-V1.2-3 / WP-V1.2-4).
 *
 * These assertions cover the welcome card's emitted shape and copy.
 * Visual verification is operator-side at acceptance.
 */

import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/index.js";

describe("v1.1 dashboard welcome card (Finding EE)", () => {
  it("emits the 'What you can do today' welcome card at the dashboard route", () => {
    const script = getClientScript();
    // The dashboard route now calls renderDashboardWelcome, not renderChatThread.
    expect(script).toContain('case "dashboard": main.innerHTML = renderDashboardWelcome();');
    expect(script).toContain("function renderDashboardWelcome()");
    expect(script).toContain("What you can do today");
  });

  it("welcome card maps every operator-actionable nav target to a one-line action descriptor", () => {
    const script = getClientScript();
    // Anchor links to all six operator nav targets — slugs verified to
    // match client.ts:282-290 hash-route IDs.
    expect(script).toContain('href="#agents"');
    expect(script).toContain('href="#policy"');
    expect(script).toContain('href="#privacy"');
    expect(script).toContain('href="#coordination"');
    expect(script).toContain('href="#health"');
    expect(script).toContain('href="#exit-drill"');
    // Coordinator-approved descriptors (with the three softens):
    //   - Policy drops "and tighten where needed"
    //   - Privacy reframes as flow visibility, not redact/hash/deny
    //   - Coordination drops "and policy peers"
    expect(script).toContain("Pause, resume, restart, lockdown, or unwrap any wrapped harness.");
    expect(script).toContain("Review the active policy bound to each agent.");
    expect(script).toContain("See what context is flowing to which provider per channel.");
    expect(script).toContain("Inspect intra-fortress agent coordination state.");
    expect(script).toContain("Check fortress posture, cocoon status, and dashboard refresh.");
    expect(script).toContain("Snapshot, verify, and prepare a portable exit bundle.");
  });

  it("welcome card explicitly defers concierge chat to v1.2", () => {
    const script = getClientScript();
    expect(script).toContain("Direct chat with the concierge ships in v1.2.");
  });

  it("welcome card uses no em-dashes (public-facing copy hard gate)", () => {
    const script = getClientScript();
    // Slice out just the welcome function body.
    const fnMatch = script.match(/function renderDashboardWelcome\(\)\s*\{[\s\S]+?return\s*\[[\s\S]+?\]\.join/);
    expect(fnMatch).toBeTruthy();
    if (fnMatch) {
      const body = fnMatch[0];
      // Em-dash is U+2014. The no-em-dash rule applies to all public-facing
      // copy; the welcome card is operator-visible.
      expect(body).not.toMatch(/—/);
    }
  });

  it("removes the v1.1.6 'Suggestion to concierge' text input", () => {
    const script = getClientScript();
    // Negative anchor on the literal v1.1.6 placeholder copy that
    // operators reported as confusing.
    expect(script).not.toContain("Suggestion to concierge");
    expect(script).not.toContain("Direct commands land in v1.2");
    expect(script).not.toContain('id="chat-input"');
    expect(script).not.toContain('id="chat-composer"');
  });
});
