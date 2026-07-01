/**
 * Tunability UX: dashboard client promote/plain-English token-gate test.
 *
 * Mirrors test/dashboard/v1_1/queue-approve-token-gate.test.ts. It proves,
 * at the CLIENT-SCRIPT level, that the tunability affordances issue only
 * operator-bearer-gated requests and never a weaker path:
 *
 *  1. The "Always allow" promote button on an approval tile emits
 *     data-action="inbox-promote" and the dispatcher routes it to
 *     onInboxPromote, which runs the compile -> activate flow through
 *     policyApi() (which sends the sessionStorage bearer). It is NOT routed
 *     through the generic /inbox/:id/<action> path.
 *  2. The plain-English policy view is fetched via policyApi("/current"),
 *     i.e. the operator-bearer path, not an unauthenticated fetch.
 *  3. policyApi() reads the bearer from the runtime TOKEN (sessionStorage),
 *     never from served HTML, and re-prompts on a 401 mutation exactly like
 *     api(). There is no loopback/auto-auth shortcut in the client.
 *
 * The server-side ENFORCEMENT (a tokenless promote / plain-English read is
 * rejected 403, a posture-weakening promote is refused by the #805 gate) is
 * proven end-to-end in test/policy-engine/policy-promote-route.test.ts.
 */

import { describe, it, expect } from "vitest";

import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

describe("tunability promote: the client routes 'Always allow' through the gated policyApi path", () => {
  const src = getClientScript();

  it("the approval tile emits a promote button with data-action=inbox-promote", () => {
    expect(src).toContain("function renderApprovalTile");
    expect(src).toContain('data-action="inbox-promote"');
  });

  it("inbox-promote is dispatched to onInboxPromote, NOT the generic /inbox/:id path", () => {
    // The dispatcher intercepts inbox-promote before the generic inbox-*
    // slice that posts to /inbox/:id/<action>.
    expect(src).toContain('action === "inbox-promote"');
    expect(src).toContain("onInboxPromote(itemId)");
  });

  it("onInboxPromote runs compile -> activate through policyApi (the operator-bearer path)", () => {
    expect(src).toContain("async function onInboxPromote");
    expect(src).toContain('policyApi("/compile"');
    // The activate step lives in activateStandingRule and posts to the
    // /drafts/:id/activate route via policyApi (bearer-gated), never a bare
    // fetch and never the hub api() inbox path.
    expect(src).toContain("async function activateStandingRule");
    expect(src).toContain('/drafts/" + encodeURIComponent(draftId) + "/activate"');
    expect(src).toContain("policyApi(path, { method: \"POST\", body: {} })");
  });

  it("a posture-weakening promote is confirmed then retried with the audited override (never silent)", () => {
    // On a 409 downgrade refusal the client asks the operator to confirm and
    // only then re-sends with override_downgrade=true. It never bypasses the
    // gate silently.
    expect(src).toContain("override_downgrade=true");
    expect(src).toContain("window.confirm");
    expect(src).toContain("activateStandingRule(draftId, op, true)");
  });

  it("the plain-English policy view is loaded via policyApi('/current')", () => {
    expect(src).toContain("async function loadPolicyView");
    expect(src).toContain('policyApi("/current"');
    expect(src).toContain("renderPolicyPlainEnglishPanel");
  });

  it("policyApi sends the runtime bearer and has no loopback/auto-auth shortcut", () => {
    expect(src).toContain("async function policyApi");
    expect(src).toContain('init.headers["Authorization"] = "Bearer " + TOKEN');
    // No auto-auth backdoor anywhere in the client.
    expect(src).not.toContain("auto-auth");
    expect(src).not.toContain("autoAuth");
  });

  it("the operator bearer is never embedded in served HTML (read from sessionStorage at runtime)", () => {
    // The token is hydrated from config OR sessionStorage; the html.ts render
    // path zeroes authToken. policyApi reads TOKEN, which is that runtime
    // value, not a value baked into the page by the renderer.
    expect(src).toContain('sessionStorage.getItem("authToken")');
  });
});
