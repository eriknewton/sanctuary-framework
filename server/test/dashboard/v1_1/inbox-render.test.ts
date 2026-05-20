/**
 * Sanctuary v1.1 Dashboard — Inbox six-kind render tests.
 *
 * Covers required test 1: each HubInboxItem kind produces the correct
 * action surface. Tier 1 approval_pending refuses dismiss action.
 *
 * The client script holds the per-kind action surface in `inboxActions`.
 * We exercise it through the embedded client module by lifting the
 * function into a vitest sandbox. This is the same approach used by
 * other dashboard standalone tests.
 */

import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

/**
 * Lift the embedded `inboxActions` function out of the client script
 * into a callable JS function. We extract the function source by regex
 * then `new Function` it. Same trick used by sse-reconnect.test.ts.
 */
function liftInboxActionsFn(): (item: unknown) => string[] {
  const src = getClientScript();
  // Match: function inboxActions(item) { ... } until the closing brace
  // before the const INBOX_ACTION_LABEL line.
  const m = src.match(/function inboxActions\(item\)\s*\{[\s\S]+?\n\}\n/);
  if (!m) throw new Error("inboxActions function not found in client script");
  const body = m[0];
  // Wrap as an IIFE returning the function.
  // eslint-disable-next-line no-new-func
  const factory = new Function(
    body + "\nreturn inboxActions;",
  ) as () => (item: unknown) => string[];
  return factory();
}

describe("v1.1 dashboard inbox six-kind render", () => {
  const inboxActions = liftInboxActionsFn();

  it("Tier 1 approval_pending exposes only approve + deny (no dismiss)", () => {
    const item = { kind: "approval_pending", tier: "tier1" };
    const acts = inboxActions(item);
    expect(acts).toContain("approve");
    expect(acts).toContain("deny");
    expect(acts).not.toContain("dismiss");
  });

  it("Tier 2 approval_pending exposes approve + deny + dismiss", () => {
    const item = { kind: "approval_pending", tier: "tier2" };
    const acts = inboxActions(item);
    expect(acts).toContain("approve");
    expect(acts).toContain("deny");
    expect(acts).toContain("dismiss");
  });

  it("blocked_egress exposes dismiss + review_receipt", () => {
    const acts = inboxActions({ kind: "blocked_egress" });
    expect(acts).toContain("dismiss");
    expect(acts).toContain("review_receipt");
  });

  it("privacy_event exposes only open_filter_event", () => {
    const acts = inboxActions({ kind: "privacy_event" });
    expect(acts).toEqual(["open_filter_event"]);
  });

  it("budget_warning exposes dismiss", () => {
    const acts = inboxActions({ kind: "budget_warning" });
    expect(acts).toContain("dismiss");
  });

  it("recovery_prompt exposes dismiss + schedule_drill", () => {
    const acts = inboxActions({ kind: "recovery_prompt" });
    expect(acts).toContain("dismiss");
    expect(acts).toContain("schedule_drill");
  });

  it("agent_error exposes dismiss + view_log", () => {
    const acts = inboxActions({ kind: "agent_error" });
    expect(acts).toContain("dismiss");
    expect(acts).toContain("view_log");
  });

  it("client template registry includes fortress lockdown copy", () => {
    const src = getClientScript();
    expect(src).toContain("approval_pending.tier1.fortress_lockdown");
    expect(src).toContain("Lockdown approval pending");
    expect(src).not.toContain("[unrecognized template: tier1]");
  });
});
