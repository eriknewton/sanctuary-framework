/**
 * Sanctuary v1.2 Dashboard — Concierge surface (WP-V1.2-4)
 *
 * v1.1.7 shipped a static "What you can do today" landing card on the
 * Dashboard view (Finding EE follow-up to v1.1.6's half-built chat
 * affordance). v1.2 replaces it with the operator-facing concierge
 * surface: chat panel as the central Dashboard surface, "Sanctuary
 * Fortress concierge" persona, suggested-action chips at the bottom.
 *
 * The substrate selector (WP-V1.2-5) backs the LLM call; until the
 * operator picks a substrate or until Ollama is reachable, the
 * concierge surfaces the honest "substrate not configured" state in
 * the badge so the operator knows exactly what is happening.
 *
 * These assertions cover the embedded client script's emitted shape
 * for the dashboard route. Visual verification is operator-side at
 * acceptance via the spawn-prompt's mandatory real-browser drill.
 */

import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/index.js";

describe("v1.2 dashboard concierge surface (WP-V1.2-4)", () => {
  it("dashboard route invokes renderDashboardConcierge (replaces v1.1.7 welcome card)", () => {
    const script = getClientScript();
    // v1.2.0-rc.1 Finding UU: route dispatch was refactored to write
    // through a render-cache so unchanged HTML does not blow away the
    // chat-history DOM (and any active text selection). The dispatch is
    // now `nextHtml = renderDashboardConcierge();` followed by a cache
    // compare; assert both pieces.
    expect(script).toContain('case "dashboard": nextHtml = renderDashboardConcierge();');
    expect(script).toContain("function renderDashboardConcierge()");
  });

  it("v1.2.0-rc.1 Finding UU: renderMain caches HTML and skips innerHTML write on no-op poll", () => {
    const script = getClientScript();
    // Cache structure declared at module scope.
    expect(script).toContain("__renderCache");
    // Cache compare branch present (skip write when route + html match).
    expect(script).toContain("__renderCache.route === state.route && __renderCache.html === nextHtml");
    // Cache update + write branch present.
    expect(script).toContain("__renderCache.route = state.route");
    expect(script).toContain("__renderCache.html = nextHtml");
  });

  it("concierge surface presents the 'Sanctuary Fortress concierge' persona inline", () => {
    const script = getClientScript();
    expect(script).toContain("Sanctuary Fortress concierge");
    expect(script).toContain("read-only over fortress state");
  });

  it("concierge surface renders chat history + composer + send button + suggestion chips", () => {
    const script = getClientScript();
    // Chat history container (host the rendered messages).
    expect(script).toContain('id="concierge-history"');
    // Composer is a form so the Enter-key submits naturally.
    expect(script).toContain('class="concierge-composer"');
    expect(script).toContain('data-action="concierge-submit"');
    // Send button + composer input both wired through data-action.
    expect(script).toContain('data-action="concierge-send"');
    expect(script).toContain('data-action="concierge-input"');
    // Suggestion chips are hardcoded at v1.2 per spawn-prompt section 4.1
    // (LLM-suggested chips defer to v1.3+).
    expect(script).toContain("CONCIERGE_SUGGESTIONS");
    expect(script).toContain('data-action="concierge-suggestion"');
    expect(script).toContain("summarize the last hour");
  });

  it("concierge submit handler hits POST /chat/concierge through the hub api", () => {
    const script = getClientScript();
    expect(script).toContain('async function onConciergeSend()');
    expect(script).toContain('await api("/chat/concierge", {');
    expect(script).toContain('method: "POST"');
    expect(script).toContain('await fetchConciergeHistory();');
  });

  it("concierge boot path hydrates history on every fetchAll cycle", () => {
    const script = getClientScript();
    expect(script).toContain('await fetchConciergeHistory();');
    // Direct-agent surface removed in the v1.2 reshape; the inspect
    // panel is fetched lazily on click rather than maintained in state.
    expect(script).not.toContain('await fetchActiveSessions();');
  });

  it("concierge surface uses no em-dashes (public-facing copy hard gate)", () => {
    const script = getClientScript();
    // The em-dash rule applies to operator-visible copy. Locate the
    // concierge render function and assert no U+2014 inside.
    const fnMatch = script.match(/function renderDashboardConcierge\(\)\s*\{[\s\S]+?\.join\("\\\\n"|function renderDashboardConcierge\(\)\s*\{[\s\S]+?\.join\("\\n"|function renderDashboardConcierge\(\)\s*\{[\s\S]+?return\s*\[[\s\S]+?\]\.join/);
    expect(fnMatch).toBeTruthy();
    if (fnMatch) {
      expect(fnMatch[0]).not.toMatch(/—/);
    }
  });

  it("retires the v1.1.6 'Suggestion to concierge' stub copy", () => {
    const script = getClientScript();
    expect(script).not.toContain("Suggestion to concierge");
    expect(script).not.toContain("Direct commands land in v1.2");
    expect(script).not.toContain('id="chat-input"');
    expect(script).not.toContain('id="chat-composer"');
  });

  it("retires the v1.1.7 'What you can do today' landing card", () => {
    const script = getClientScript();
    // Hard-anchor on the v1.1.7 landing-card heading + the "ships in v1.2"
    // deferral copy. Both are gone in v1.2 because the concierge IS the
    // surface that v1.1.7 deferred.
    expect(script).not.toContain("<h1>What you can do today</h1>");
    expect(script).not.toContain("Direct chat with the concierge ships in v1.2.");
  });
});

describe("v1.2 dashboard click-to-inspect (WP-V1.2 reshape)", () => {
  it("agent-detail view embeds the inspect panel", () => {
    const script = getClientScript();
    expect(script).toContain("function renderAgentInspectPanel(agent)");
    // The agent-detail render calls into renderAgentInspectPanel and
    // appends the panel between the identity card and the timeline.
    expect(script).toContain("const inspectPanel = renderAgentInspectPanel(a);");
  });

  it("inspect CTA uses the click-to-inspect framing copy (read-only)", () => {
    const script = getClientScript();
    // The CTA opens a read-only inspect panel; no chat session, no
    // Tier 1 approval ask, the click is a plain navigate.
    expect(script).toContain('data-action="agent-inspect-open"');
    expect(script).toContain(">Open inspect panel<");
    // Hard-anchor against direct-agent chat framing.
    expect(script).not.toContain(">Open direct chat<");
    expect(script).not.toContain('data-action="direct-agent-start"');
  });

  it("inspect-open handler hits the new /agents/:id/inspect/open route", () => {
    const script = getClientScript();
    expect(script).toContain("async function onAgentInspectOpen(agentId)");
    expect(script).toContain('"/agents/" + encodeURIComponent(agentId) + "/inspect/open"');
    // Optimistic-render keyed on openingAgentId while the round-trip
    // is in flight.
    expect(script).toContain("openingAgentId");
  });

  it("direct-agent send + end handlers are removed", () => {
    const script = getClientScript();
    expect(script).not.toContain("async function onDirectAgentSend");
    expect(script).not.toContain("async function onDirectAgentEnd");
    expect(script).not.toContain('/chat/agents/');
  });

  it("inspect panel uses no em-dashes (public-facing copy hard gate)", () => {
    const script = getClientScript();
    const fnMatch = script.match(/function renderAgentInspectPanel\(agent\)\s*\{[\s\S]+?return\s*'<div class="card">'[\s\S]+?'<\/div>';\n\s*\}/);
    expect(fnMatch).toBeTruthy();
    if (fnMatch) {
      expect(fnMatch[0]).not.toMatch(/—/);
    }
  });
});
