/**
 * Sanctuary v1.1 Dashboard — Intelligence Panel HTML / Client tests
 *
 * The dashboard ships an inline ESM client script that owns the panel
 * render. These tests assert the structural invariants of that client:
 *
 *   - Sidebar nav contains Intelligence between Policy and Privacy.
 *   - Panel route lands in the renderMain switch.
 *   - Picker modal renders the four operator-pickable substrates plus
 *     Disabled with their tradeoff text.
 *   - No-em-dash sweep on the Intelligence-specific operator-visible copy.
 *   - Naming-discipline: composition partners named (Ollama, Venice.ai,
 *     Anthropic, OpenAI, Google); no specific competitors mentioned.
 *   - Stable badge label + tradeoff strings mirror the backend fallback
 *     registry verbatim (the test consumes both maps and asserts equality).
 *
 * These are HTML-shape and client-script string-shape tests; the
 * integration exercise lives in
 * `intelligence-api-router.test.ts` for the wire layer and
 * `intelligence-real-browser-drill.test.ts` for the real-DOM drill.
 */

import { describe, expect, it } from "vitest";
import {
  renderDashboardV11Html,
  getClientScript,
} from "../../../src/dashboard/v1_1/index.js";
import {
  BACKEND_FALLBACK_STRINGS,
  BADGE_LABEL_KEYS,
  BADGE_TRADEOFF_KEYS,
  LOCAL_MODEL_LABELS,
} from "../../../src/intelligence/templates.js";

describe("Intelligence panel — sidebar nav + route plumbing", () => {
  it("includes Intelligence in the sidebar nav between Policy and Privacy", () => {
    const html = renderDashboardV11Html({});
    expect(html).toContain('data-route="intelligence"');
    const policyIdx = html.indexOf('data-route="policy"');
    const intelIdx = html.indexOf('data-route="intelligence"');
    const privacyIdx = html.indexOf('data-route="privacy"');
    expect(policyIdx).toBeGreaterThan(0);
    expect(intelIdx).toBeGreaterThan(policyIdx);
    expect(privacyIdx).toBeGreaterThan(intelIdx);
  });

  it("client-script renderMain dispatches the intelligence route to renderIntelligenceCenter", () => {
    const client = getClientScript();
    expect(client).toContain('case "intelligence":');
    expect(client).toContain("renderIntelligenceCenter()");
  });

  it("client-script declares the four operator-pickable substrates plus Disabled", () => {
    const client = getClientScript();
    // SUBSTRATE_OPTIONS is the picker's source-of-truth array.
    expect(client).toMatch(/SUBSTRATE_OPTIONS\s*=\s*\[\s*"local",\s*"venice",\s*"frontier-with-filter",\s*"hybrid",\s*"disabled"\s*\]/);
  });

  it("client-script declares all six surfaces in the Surfaces panel", () => {
    const client = getClientScript();
    for (const surface of [
      "concierge",
      "direct-agent-gate-advisor",
      "sentinel-scoring",
      "gate-explanation",
      "privacy-filter-tier-2",
      "template-suggestion",
    ]) {
      expect(client).toContain(`"${surface}"`);
    }
  });
});

describe("Intelligence panel — copy invariants", () => {
  it("client-script substrate label / tradeoff strings mirror the backend fallback registry verbatim", () => {
    const client = getClientScript();
    // Each backend fallback string appears verbatim in the client script.
    for (const choice of ["local", "venice", "frontier-with-filter", "hybrid", "disabled"] as const) {
      const label = BACKEND_FALLBACK_STRINGS[BADGE_LABEL_KEYS[choice]];
      const tradeoff = BACKEND_FALLBACK_STRINGS[BADGE_TRADEOFF_KEYS[choice]];
      expect(label).toBeTruthy();
      expect(tradeoff).toBeTruthy();
      expect(client).toContain(label!);
      expect(client).toContain(tradeoff!);
    }
  });

  it("client-script local-model labels mirror the backend label registry verbatim", () => {
    const client = getClientScript();
    for (const pick of ["gemma-2-2b", "phi-4-mini", "llama-3.1-8b"] as const) {
      const label = LOCAL_MODEL_LABELS[pick];
      expect(client).toContain(label);
    }
  });

  it("Intelligence-specific operator-visible copy contains no em-dashes", () => {
    const client = getClientScript();
    // Scope the em-dash sweep to the Intelligence client section. Markers:
    //   start = "// ── Render: intelligence" comment header (uses box-drawing
    //           U+2500 dashes which are NOT em-dashes; safe sentinel).
    //   end   = "// ── Render: policy" comment header for the next section.
    const start = client.indexOf("Render: intelligence");
    const end = client.indexOf("Render: policy");
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const window = client.slice(start, end);
    expect(window).not.toContain("—"); // U+2014 EM DASH
  });

  it("client-script names composition partners (Ollama, Venice.ai) and avoids specific competitor names", () => {
    const client = getClientScript();
    expect(client).toContain("Ollama");
    expect(client).toContain("Venice");
    // No-competitor sweep — naming-discipline rule.
    const competitorTerms = [
      "Coze", "Lindy", "Dust", "Hermes", "MoltBridge", "AgentGraph",
      "HiveTrust", "OpenAgent", "Mastra", "Cline", "Dify",
    ];
    for (const term of competitorTerms) {
      expect(client).not.toContain(term);
    }
  });

  it("frontier substrate tradeoff text explicitly names the leakage with required caveat", () => {
    const client = getClientScript();
    // Honesty floor: frontier-with-filter must not claim cryptographic
    // privacy. The phrase "expect imperfect privacy" is the required
    // caveat from the position paper §5.
    const frontierTradeoff = BACKEND_FALLBACK_STRINGS[BADGE_TRADEOFF_KEYS["frontier-with-filter"]];
    expect(frontierTradeoff).toContain("imperfect privacy");
    expect(client).toContain("imperfect privacy");
  });
});

describe("Intelligence panel — CSS shell", () => {
  it("renders the .intel-modal-backdrop class so picker modal CSS is reachable", () => {
    const html = renderDashboardV11Html({});
    expect(html).toContain(".intel-modal-backdrop");
    expect(html).toContain(".intel-row");
    expect(html).toContain(".intel-status-dot");
  });

  it("renders responsive breakpoint that collapses .intel-row at narrow widths", () => {
    const html = renderDashboardV11Html({});
    // The 1100px breakpoint flips the per-surface row to single-column.
    expect(html).toMatch(/@media\s*\(max-width:\s*1100px\)/);
    // Within that breakpoint, .intel-row collapses to 1fr.
    const breakpointStart = html.indexOf("@media (max-width: 1100px)");
    const breakpointBody = html.slice(breakpointStart, breakpointStart + 600);
    expect(breakpointBody).toContain(".intel-row");
  });
});

describe("Intelligence panel — sidebar nav welcome card link", () => {
  it("welcome card links to the Intelligence route so first-time operators discover it", () => {
    const client = getClientScript();
    expect(client).toContain('href="#intelligence"');
  });
});

describe("Intelligence panel — CCCC first-load render + substrate-missing wording", () => {
  it("notConfigured empty-state names the missing config and gives the exact command (NNNNN pattern)", () => {
    const client = getClientScript();
    expect(client).toContain("No intelligence substrate configured");
    expect(client).toContain("sanctuary intelligence configure --substrate local");
  });

  it("notConfigured empty-state lists all three substrate options (local, hosted, hybrid)", () => {
    const client = getClientScript();
    // The notConfigured block should reference all three substrate choices
    // so the operator knows what their options are.
    expect(client).toContain("--substrate local");
    expect(client).toContain("--substrate hosted");
    expect(client).toContain("--substrate hybrid");
  });

  it("loadError state shows substrate-configuration guidance for new fortresses", () => {
    const client = getClientScript();
    expect(client).toContain("If this is a new fortress, configure a substrate first");
    expect(client).toContain("sanctuary intelligence configure --substrate local");
  });

  it("fetchIntelligenceState handles 401 with a dashboard-auth-specific message, not raw 'unauthorized'", () => {
    const client = getClientScript();
    // The client must NOT surface the raw "unauthorized" string from the
    // auth middleware as the loadError. Instead, it must provide an
    // actionable message naming the auth issue and how to fix it.
    expect(client).toContain("e.status === 401");
    expect(client).toContain("Dashboard authentication required");
    expect(client).toContain("sanctuary dashboard --fortress");
  });

  it("pre-fix code path (substrate-missing showing raw 'unauthorized') no longer fires", () => {
    const client = getClientScript();
    // The fetchIntelligenceState function must intercept 401 errors
    // BEFORE the generic loadError assignment, so the raw "unauthorized"
    // string from auth-middleware never reaches state.intelligence.loadError.
    const fetchFn = client.slice(
      client.indexOf("async function fetchIntelligenceState()"),
      client.indexOf("async function onIntelPickerOpen(")
    );
    // 401 check must appear before the generic loadError fallback
    const idx401 = fetchFn.indexOf("e.status === 401");
    const idxGeneric = fetchFn.indexOf("state.intelligence.loadError = e.message");
    expect(idx401).toBeGreaterThan(0);
    expect(idxGeneric).toBeGreaterThan(idx401);
  });
});
