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
    expect(script).toContain('case "dashboard": main.innerHTML = renderDashboardConcierge();');
    expect(script).toContain("function renderDashboardConcierge()");
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

  it("concierge boot path hydrates history + active sessions on every fetchAll cycle", () => {
    const script = getClientScript();
    expect(script).toContain('await fetchConciergeHistory();');
    expect(script).toContain('await fetchActiveSessions();');
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

describe("v1.2 dashboard direct-agent chat (WP-V1.2-4)", () => {
  it("agent-detail view embeds the direct-agent chat panel", () => {
    const script = getClientScript();
    expect(script).toContain("function renderDirectAgentChat(agent)");
    // The agent-detail render calls into renderDirectAgentChat and
    // appends the panel between the identity card and the timeline.
    expect(script).toContain("const chatPanel = renderDirectAgentChat(a);");
  });

  it("direct-agent CTA emits the Tier 1 framing copy", () => {
    const script = getClientScript();
    expect(script).toContain("Open direct chat (Tier 1)");
    expect(script).toContain('data-action="direct-agent-start"');
  });

  it("direct-agent start handler enqueues a Tier 1 inbox item", () => {
    const script = getClientScript();
    expect(script).toContain("async function onDirectAgentStart(agentId)");
    expect(script).toContain('"/chat/agents/" + encodeURIComponent(agentId) + "/session/start"');
    // Pending inbox-item id is tracked per agent so the CTA hides and
    // the "approve in inbox" hint appears between session-start and
    // session-open.
    expect(script).toContain("pendingApprovalByAgentId");
  });

  it("direct-agent send + end handlers exist and route through hub api", () => {
    const script = getClientScript();
    expect(script).toContain("async function onDirectAgentSend(agentId)");
    expect(script).toContain('"/chat/agents/" + encodeURIComponent(agentId) + "/message"');
    expect(script).toContain("async function onDirectAgentEnd(agentId)");
    expect(script).toContain('"/chat/agents/" + encodeURIComponent(agentId) + "/session/end"');
  });

  it("direct-agent surface uses no em-dashes (public-facing copy hard gate)", () => {
    const script = getClientScript();
    const fnMatch = script.match(/function renderDirectAgentChat\(agent\)\s*\{[\s\S]+?return\s*'<div class="card">'[\s\S]+?'<\/div>';\n\s*\}/);
    expect(fnMatch).toBeTruthy();
    if (fnMatch) {
      expect(fnMatch[0]).not.toMatch(/—/);
    }
  });
});
