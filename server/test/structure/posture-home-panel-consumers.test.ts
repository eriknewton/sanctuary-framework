/** All posture-home consumers carry panel freshness and unknown detection explicitly. */
import { describe, expect, it, vi } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { capStalePanel, POSTURE_PANEL_IDS } from "../../src/principal-policy/panel-producer.js";
import { getClientScript } from "../../src/dashboard/v1_1/client.js";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";
import { renderPostureAgentHTML } from "../../src/principal-policy/posture-agent-html.js";
import { REL_TIME_FN_SOURCE } from "../../src/principal-policy/posture-html-shared.js";
import { OVERVIEW_FRESHNESS_MS, auditConsumerAgreementMatrix, auditOutputClass } from "../dashboard/v1_1/fixtures/overview-scenarios.js";
const root = resolve("src");
const expected = ["dashboard/v1_1/client.ts", "principal-policy/posture-agent-html.ts", "principal-policy/posture-home-html.ts"];
function files(path: string): string[] {
  return readdirSync(path, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(join(path, entry.name)) : entry.name.endsWith(".ts") ? [join(path, entry.name)] : []);
}
function functionSource(script: string, name: string): string {
  const start = script.indexOf(`function ${name}(`);
  expect(start).toBeGreaterThanOrEqual(0);
  let position = script.indexOf("{", start), depth = 1;
  while (depth > 0 && position < script.length) { position++; if (script[position] === "{") depth++; if (script[position] === "}") depth--; }
  expect(depth).toBe(0);
  return script.slice(start, position + 1);
}
describe("posture-home consumer contract", () => {
  it("pins the full fetching consumer set and every additive status reader", () => {
    const consumers = files(root).filter(file => /(?:api|fetch|credentialedReadUrl|readResponse)\(["'`]\/api\/posture\/home/.test(readFileSync(file, "utf8")));
    expect(consumers.map(file => relative(root, file)).sort()).toEqual(expected);
    for (const file of consumers) {
      const source = readFileSync(file, "utf8");
      expect(source).toContain("panels"); expect(source).toContain("audit_verification");
      expect(source).toContain("Last checked "); expect(source).toContain("Not available right now");
      expect(source).toContain("more entries are checked in full on every pass");
    }
  });
  it("SPA detection is unknown when the unwrapped producer is unavailable", () => {
    const fn = new Function(functionSource(getClientScript(), "unprotectedHarnesses") + "; return unprotectedHarnesses;")();
    expect(fn({ unwrapped: { unwrapped: [] }, panels: { unwrapped: { state: "unavailable" } } })).toBeNull();
    expect(fn({ unwrapped: { unwrapped: [] }, panels: { unwrapped: { state: "fresh" } } })).toEqual([]);
  });
  it("home HTML detection denominator remains unknown for an unavailable scan", () => {
    const script = renderPostureHomeHTML();
    const expression = script.slice(script.indexOf("var detectedTotal ="), script.indexOf("var wallEvidenceAt", script.indexOf("var detectedTotal =")));
    const read = new Function("home", expression + "; return detectedTotal;");
    expect(read({ agents: [], unwrapped: { unwrapped: [] }, panels: { unwrapped: { state: "unavailable" } } })).toBe("Unknown");
  });
  it("agent HTML labels unavailable detection explicitly", () => {
    const script = renderPostureAgentHTML();
    const line = script.split("\n").find(line => line.includes('standing.innerHTML +=') && line.includes("Detected harnesses"));
    expect(line).toBeDefined();
    const standing = { innerHTML: "" };
    new Function("home", "standing", line!)({ panels: { unwrapped: { state: "unavailable" } } }, standing);
    expect(standing.innerHTML).toContain("Unknown");
  });
});

const panelIds = POSTURE_PANEL_IDS;
const states = ["fresh", "stale", "unavailable"] as const;
const AGE_MS = 12_000; // Twelve seconds makes the displayed age distinguishable from a default zero.
function statusHome(id: string, state: string) {
  return { panels: Object.fromEntries(panelIds.map(key => [key, { state: key === id ? state : "fresh", age_ms: AGE_MS }])),
    audit_verification: { verified_uncached_last_pass: 0 } };
}
function documentFixture(ids: string[]) {
  const elements = Object.fromEntries(ids.map(id => [id, { innerHTML: `content:${id}`, querySelectorAll: () => [] }]));
  return { elements, document: { getElementById: (id: string) => elements[id] } };
}
it.each(panelIds)("SPA status content handles all states for %s", id => {
  const script = getClientScript();
  const render = new Function("escHtml", "durationLabelFromMs", functionSource(script, "posturePanelNote") + functionSource(script, "posturePanelContent") + "; return posturePanelContent;")(String, (ms: number) => `${ms / 1000}s`);
  expect(render(statusHome(id, "fresh"), id, "panel-content")).toBe("panel-content");
  expect(render(statusHome(id, "stale"), id, "panel-content")).toContain("panel-content<p");
  expect(render(statusHome(id, "stale"), id, "panel-content")).toContain("Last checked 12s ago");
  expect(render(statusHome(id, "unavailable"), id, "panel-content")).toContain("Not available right now");
  expect(render(statusHome(id, "unavailable"), id, "panel-content")).not.toContain("panel-content");
  expect(render({}, id, "panel-content")).toBe("panel-content");
});
const homeTargets = { castle_wall: "wall", digest: "story", feature_health: "features", custody_exit: "custody", query_privacy: "queryprivacy", agents_roster: "agents", federation: "fleet" };
it.each(Object.entries(homeTargets))("home HTML applies every status to %s and preserves independent panels", (id, target) => {
  for (const state of states) {
    const { elements, document } = documentFixture(Object.values(homeTargets));
    const render = new Function("document", "esc", functionSource(renderPostureHomeHTML(), "renderPanelStatus") + "; return renderPanelStatus;")(document, String);
    render(statusHome(id, state));
    if (state === "fresh") expect(elements[target].innerHTML).toBe(`content:${target}`);
    if (state === "stale") expect(elements[target].innerHTML).toContain(`content:${target}<p class="meta">Last checked 12s ago`);
    if (state === "unavailable") expect(elements[target].innerHTML).toBe('<p class="empty">Not available right now</p>');
    for (const other of Object.values(homeTargets).filter(key => key !== target)) expect(elements[other].innerHTML).toBe(`content:${other}`);
  }
});
it("home HTML scan status preserves the registered roster and reports stale detection age", () => {
  const script = renderPostureHomeHTML();
  const { elements, document } = documentFixture(Object.values(homeTargets));
  const status = new Function("document", "esc", REL_TIME_FN_SOURCE + functionSource(script, "renderPanelStatus") + "; return renderPanelStatus;")(document, String);
  status(statusHome("unwrapped", "stale"));
  expect(elements.agents.innerHTML).toContain('content:agents<p class="meta">Last checked 12s ago');
  const agents = new Function("document", "esc", functionSource(script, "renderAgents") + "; return renderAgents;")(document, String);
  agents({ ...statusHome("unwrapped", "unavailable"), agents: [], unwrapped: { unwrapped: [{ harness: "hidden scan result" }] } });
  expect(elements.agents.innerHTML).toContain("Not available right now");
  expect(elements.agents.innerHTML).not.toContain("hidden scan result");
});
it.each(["agents_roster", "unwrapped"])("agent HTML handles every displayed status for %s", id => {
  for (const state of states) {
    const { elements, document } = documentFixture(["standing"]);
    const render = new Function("document", "esc", REL_TIME_FN_SOURCE + functionSource(renderPostureAgentHTML(), "renderPanelStatus") + "; return renderPanelStatus;")(document, String);
    render(statusHome(id, state));
    if (state === "fresh") expect(elements.standing.innerHTML).toBe("content:standing");
    if (state === "stale") expect(elements.standing.innerHTML).toContain("Last checked 12s ago");
    if (state === "unavailable") {
      expect(elements.standing.innerHTML).toContain("Not available right now");
      if (id === "agents_roster") expect(elements.standing.innerHTML).not.toContain("content:standing");
      else expect(elements.standing.innerHTML).toContain("Detected harnesses: Unknown");
    }
  }
});
it.each([0, 3])("every consumer displays verification overflow only when positive (%s)", count => {
  const home = { ...statusHome("digest", "fresh"), audit_verification: { verified_uncached_last_pass: count } };
  const spa = new Function("escHtml", functionSource(getClientScript(), "auditVerificationNote") + "; return auditVerificationNote;")(String)(home);
  const outputs = [spa];
  for (const [script, target] of [[renderPostureHomeHTML(), "story"], [renderPostureAgentHTML(), "standing"]]) {
    const { elements, document } = documentFixture([...Object.values(homeTargets), "standing"]);
    new Function("document", "esc", REL_TIME_FN_SOURCE + functionSource(script, "renderPanelStatus") + "; return renderPanelStatus;")(document, String)(home);
    outputs.push(elements[target].innerHTML);
  }
  for (const output of outputs) {
    if (count > 0) expect(output).toContain("3 more entries are checked in full on every pass");
    else expect(output).not.toContain("more entries are checked in full on every pass");
  }
});

it("connects status rendering to every displayed home consumer", () => {
  expect(functionSource(renderPostureHomeHTML(), "renderHome")).toContain("renderPanelStatus(home)");
  expect(renderPostureAgentHTML()).toContain("renderStanding(row);\n          renderPanelStatus(home);");
  const spa = getClientScript();
  const overview = functionSource(spa, "renderPostureScreen");
  for (const id of ["castle_wall", "digest"]) expect(overview).toContain('posturePanelNote(home, "' + id + '")');
  for (const id of ["digest", "agents_roster", "unwrapped"]) expect(overview).toContain('posturePanelContent(home, "' + id + '",');
  expect(functionSource(spa, "renderAgentsList")).toContain('posturePanelContent(home, "unwrapped", tiles)');
  for (const id of ["digest", "agents_roster"]) expect(functionSource(spa, "renderEnforcementScreen")).toContain('posturePanelContent(home, "' + id + '",');
});
it.each(["stale", "unavailable"])("SPA wall cannot show enforcing over a %s panel", state => {
  const render = new Function("state", "sourceLoaded", "evidenceCurrent", functionSource(getClientScript(), "postureWallLabel") + "; return postureWallLabel;")(
    { posture: { home: statusHome("castle_wall", state) } }, () => true, () => true);
  expect(render("armed")).toEqual({ cls: "pill tone-unknown", text: "Unknown" });
});

it.each(["stale", "unavailable"])("SPA protection counts are Unknown for a %s roster", state => {
  const script = getClientScript();
  const render = new Function("sourceLoaded", "unprotectedHarnesses", "servedCount", "overviewSourceReason", "overviewTile", "escHtml", "overviewChip", "loadedSourceReadAge",
    functionSource(script, "renderOverviewProtection") + "; return renderOverviewProtection;")(
    () => true, () => [], Number.isFinite, () => "fixture", (...args: string[]) => args.join(" "), String,
    (_tone: string, label: string) => label, () => "now");
  const home = { protection_requested_count: 0, protection_detected_count: 2, panels: { agents_roster: { state } } };
  expect(render(home)).toContain("UNKNOWN");
  expect(render(home)).not.toContain("0 of 2");
  home.panels.agents_roster.state = "fresh";
  expect(render(home)).toContain("0 of 2");
});

it("pins the closed reason set in all consumer copy tables", () => {
  const reasons = ["budget_exceeded", "producer_failed", "never_completed", "upstream_unavailable", "observation_superseded"];
  const source = readFileSync(join(root, "principal-policy/panel-producer.ts"), "utf8");
  expect([...source.match(/export type PosturePanelReason = ([^;]+);/)![1].matchAll(/"([^"]+)"/g)].map(match => match[1])).toEqual(reasons);
  for (const script of [getClientScript(), renderPostureHomeHTML(), renderPostureAgentHTML()]) {
    const table = script.match(/(?:var|const) reasons = \{([^}]+)\}/)![1];
    expect([...table.matchAll(/(\w+):/g)].map(match => match[1])).toEqual(reasons);
  }
});

it("gates every roster count in the complete home banner", () => {
  const script = renderPostureHomeHTML();
  const render = new Function("document", "wallPill", "auditChainPill", "esc", "approvalsWaitingValue", "relTime", functionSource(script, "stat") + functionSource(script, "renderBanner") + "; return renderBanner;");
  for (const state of ["unavailable", "stale", "fresh"]) {
    const { elements, document } = documentFixture(["banner", "origin"]);
    const run = render(document, () => "Unknown", () => "Unknown", String, () => "Unknown", () => "");
    run({ ...statusHome("agents_roster", state), origin_machine: "fixture", agents: [], unwrapped: { unwrapped: [] },
      protection_requested_count: 0, enforcement_confirmed_count: 0, castle_wall: {}, digest: {} }, { status: "available", pending: [] }, { status: "available", findings: [] });
    const expected = state === "fresh" ? "0 of 0" : "Unknown of Unknown";
    const text = elements.banner.innerHTML.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    expect(text).toContain(expected + " Protection requested");
    expect(text).toContain(expected + " Enforcement confirmed");
    if (state !== "fresh") expect(text).not.toContain("0 of");
  }
});

it("gates the enforcement screen's complete roster heading", () => {
  const script = getClientScript();
  const render = functionSource(script, "renderEnforcementScreen");
  // Execute the production screen with independent presentation helpers stubbed.
  const helpers = { sourceLoaded: () => true, postureWallLabel: () => ({ cls: "", text: "Unknown" }),
    postureLayerLines: () => [], renderSourceRead: () => "", renderOutboundConnections: () => "",
    auditVerificationNote: () => "", renderPostureAgentRows: () => "rows", escHtml: String,
    durationLabelFromIso: () => "", durationLabelFromMs: () => "12s", renderPageHeader: () => "", layerDotClass: () => "" };
  for (const state of ["unavailable", "stale", "fresh"]) {
    const home = { ...statusHome("agents_roster", state), agents: [], castle_wall: {}, digest: {} };
    const execute = new Function("state", ...Object.keys(helpers), functionSource(script, "posturePanelNote") + functionSource(script, "posturePanelContent") + render + "; return renderEnforcementScreen;");
    const output = execute({ posture: { home } }, ...Object.values(helpers))();
    expect(output).toContain("Per-agent enforcement (" + (state === "fresh" ? "0" : "Unknown") + ")");
    if (state === "unavailable") expect(output).toContain("Not available right now");
  }
});


it("HTML consumers preserve failed and clean digests under both freshness reasons", () => {
  const homeScript = renderPostureHomeHTML();
  const pill = new Function("esc", REL_TIME_FN_SOURCE + functionSource(homeScript, "auditChainPill") + "; return auditChainPill;")(String);
  for (const verdict of ["verified", "findings"] as const) {
    for (const reason of ["observation_superseded", "budget_exceeded"] as const) {
      const digest = capStalePanel("digest", { chain_verdict: verdict, chain_verified: verdict === "verified", integrity_finding_count: verdict === "findings" ? 1 : 0 } as Parameters<typeof capStalePanel<"digest">>[1]);
      expect(digest.chain_verdict).toBe(verdict);
      const home = { ...statusHome("digest", "stale"), digest };
      Object.assign(home.panels.digest, { reason });
      const { elements, document } = documentFixture(["story", "standing"]);
      const summary = new Function("esc", "auditChainPill", "storyEvidenceFoot", functionSource(homeScript, "renderStoryPlainSummary") + "; return renderStoryPlainSummary;")(String, pill, () => "");
      const story = new Function("document", "auditChainPill", "storyEvidenceFoot", "syncStoryToggle", "readStoryPlainSummaryPreference",
        "var lastStoryDigest, lastStoryPanel;" + functionSource(homeScript, "renderStory") + "; return renderStory;")(document, pill, () => "", () => {}, () => false);
      story(digest, home.panels.digest);
      new Function("document", "esc", REL_TIME_FN_SOURCE + functionSource(renderPostureAgentHTML(), "renderPanelStatus") + "; return renderPanelStatus;")(document, String)(home);
      const outputs = [pill(digest, home.panels.digest), summary(digest, home.panels.digest), elements.story.innerHTML, elements.standing.innerHTML];
      for (const output of outputs) {
        expect(output).not.toContain('pill green');
        expect(output).not.toContain(">VERIFIED<");
        expect(output).not.toContain("verified clean");
        if (verdict === "findings") {
          expect(output).toContain("FAILED"); expect(output).toContain("1 finding"); expect(output).not.toContain("WITHHELD");
        } else {
          expect(output).not.toContain("FAILED");
          if (reason === "observation_superseded") expect(output).toContain("WITHHELD");
          else { expect(output).toContain("not current"); expect(output).not.toMatch(/UNVERIFIED|pill red|integrity finding/); }
        }
      }
    }
  }
});

it("digest authority gates current checks, counts, expiry and HTML green derivations", () => {
  const script = getClientScript();
  const current = new Function("evidenceCurrent", "auditChainEvidence", functionSource(script, "auditChainCheckCurrent") + "; return auditChainCheckCurrent;")(() => true, (value: unknown) => value);
  const expiry = new Function("auditChainCheckCurrent", "evidenceCurrent", "auditChainEvidence", "parseEvidenceTimestamp", functionSource(script, "postureHomeExpiryAt") + "; return postureHomeExpiryAt;")(
    current, (value: unknown) => !!value, (value: unknown) => value, Date.parse);
  const outbound = new Function("auditChainCheckCurrent", "windowCoverageReason", "servedCount", "parseEvidenceTimestamp", "overviewChip", "escHtml", "shortTime", "relTimeFromIso",
    functionSource(script, "renderOutboundConnections") + "; return renderOutboundConnections;")(current, () => null, Number.isSafeInteger, Date.parse, (_tone: string, label: string) => label, String, String, String);
  const digest = { chain_verified: true, chain_verdict: "verified", integrity_finding_count: 0, window_complete: true,
    window_start: "2026-01-01T00:00:00Z", window_end: "2026-01-01T00:01:00Z", kernel_blocks: 1, kernel_allows: 1, kernel_allow_overrides: 0 };
  const capped = capStalePanel("digest", digest as Parameters<typeof capStalePanel<"digest">>[1]);
  expect(capped.chain_verdict).toBe("verified");
  for (const chain_verdict of ["verified", "verified_suffix_only"]) {
    const unverified = { ...capped, chain_verdict };
    expect(current(unverified)).toBe(false);
    expect(outbound(unverified, true, { state: "stale" })).toContain("audit check not current");
    expect(outbound(unverified, true)).not.toContain("<strong>1</strong>");
    expect(expiry({ digest: unverified, agents: [] })).toBeNull();
  }
  const pill = new Function("esc", REL_TIME_FN_SOURCE + functionSource(renderPostureHomeHTML(), "auditChainPill") + "; return auditChainPill;")(String);
  expect(pill({ chain_verified: true, chain_verdict: "findings" })).not.toContain('pill green');
  expect(pill({ chain_verified: true })).not.toContain('pill green');
});


describe("audit consumer structural agreement matrix", () => {
  it("HTML banner, both stories and agent agree on every producer pair and panel clock cell", () => {
    const script = renderPostureHomeHTML();
    const pill = new Function("esc", REL_TIME_FN_SOURCE + functionSource(script, "auditChainPill") + "; return auditChainPill;")(String);
    for (const cell of auditConsumerAgreementMatrix(Date.now())) {
      const { elements, document } = documentFixture(["story", "standing"]);
      const summary = new Function("esc", "auditChainPill", "storyEvidenceFoot", functionSource(script, "renderStoryPlainSummary") + "; return renderStoryPlainSummary;")(String, pill, () => "");
      const story = new Function("document", "auditChainPill", "storyEvidenceFoot", "syncStoryToggle", "readStoryPlainSummaryPreference",
        "var lastStoryDigest, lastStoryPanel;" + functionSource(script, "renderStory") + "; return renderStory;")(document, pill, () => "", () => {}, () => false);
      story(cell.digest, cell.panel);
      const home = { ...statusHome("digest", cell.panel.state), digest: cell.digest };
      Object.assign(home.panels.digest, cell.panel);
      new Function("document", "esc", REL_TIME_FN_SOURCE + functionSource(renderPostureAgentHTML(), "renderPanelStatus") + "; return renderPanelStatus;")(document, String)(home);
      const outputs = { banner: pill(cell.digest, cell.panel), summary: summary(cell.digest, cell.panel), story: elements.story.innerHTML, agent: elements.standing.innerHTML };
      for (const [consumer, output] of Object.entries(outputs)) {
        const label = consumer + ":" + cell.name;
        expect.soft(auditOutputClass(output), label).toBe(cell.output);
        if (cell.output === "FAILED") {
          expect.soft(output, label).toContain(cell.digest.integrity_finding_count ? "1 finding" : "chain not verified");
          expect.soft(output, label).not.toContain("WITHHELD");
          expect.soft(output, label).not.toMatch(/pill (green|amber)/);
        } else if (cell.output === "GREEN") {
          expect.soft(output, label).toContain("VERIFIED");
          expect.soft(output, label).not.toMatch(/pill (red|amber)|FAILED|UNVERIFIED/);
        } else if (cell.output === "AMBER") {
          expect.soft(output, label).toContain("not re-verifiable at this privilege");
          expect.soft(output, label).not.toMatch(/pill (green|red)|UNVERIFIED/);
        } else if (cell.output === "NEUTRAL" || cell.output === "WITHHELD") {
          expect.soft(output, label).not.toMatch(/pill (green|red)|FAILED|VERIFIED|integrity finding/);
          expect.soft(output, label).toContain(cell.output === "WITHHELD" ? "observation superseded" : "not current");
        }
      }
    }
  });

  it("pins the producer clean collapse and excludes true-plus-suffix conditions", () => {
    const source = readFileSync(join(root, "principal-policy/posture.ts"), "utf8");
    expect(source).toMatch(/chain_verified: chainVerdict !== null && auditChainVerdictClaimsClean\(chainVerdict\)/);
    const verifier = readFileSync(join(root, "operational/audit-log.ts"), "utf8");
    expect(verifier).toMatch(/function auditChainVerdictClaimsClean[^]*?return v.status === "verified";/);
    // One conditional expression only: stop at statement, branch or expression boundaries.
    const impossible = /chain_verified === true\s*&&\s*(?:\([^;?:{}]*?\|\|\s*)?[\w.]+\.chain_verdict === "verified_suffix_only"/;
    const reverse = /chain_verdict === "verified_suffix_only"\s*&&\s*[\w.]+\.chain_verified === true/;
    for (const script of [getClientScript(), renderPostureHomeHTML(), renderPostureAgentHTML()]) {
      expect.soft(script).not.toMatch(impossible);
      expect.soft(script).not.toMatch(reverse);
    }
  });

  it("dates the agent audit line and expires both accepted verdicts at the shared bound", () => {
    vi.useFakeTimers();
    try {
      const now = Date.now();
      const { elements, document } = documentFixture(["standing"]);
      const render = new Function("document", "esc", REL_TIME_FN_SOURCE + functionSource(renderPostureAgentHTML(), "renderPanelStatus") + "; return renderPanelStatus;")(document, String);
      for (const verdict of ["verified", "verified_suffix_only"]) {
        vi.setSystemTime(now);
        const home = { ...statusHome("digest", "fresh"), digest: { chain_verified: verdict === "verified", chain_verdict: verdict, window_end: new Date(now).toISOString() } };
        elements.standing.innerHTML = ""; render(home);
        expect.soft(elements.standing.innerHTML).toContain(verdict === "verified" ? 'pill green' : 'pill amber');
        expect.soft(elements.standing.innerHTML).toContain("checked 0s ago");
        expect.soft(elements.standing.innerHTML).toContain(home.digest.window_end);
        vi.setSystemTime(now + OVERVIEW_FRESHNESS_MS + 1);
        elements.standing.innerHTML = ""; render(home);
        expect.soft(elements.standing.innerHTML).toContain("not current, last verified");
        expect.soft(elements.standing.innerHTML).not.toMatch(/pill (green|red|amber)/);
      }
      vi.setSystemTime(now);
      for (const window_end of [new Date(now).toISOString().replace("Z", ""), "2999-02-30T00:00:00Z", new Date(now + 1).toISOString()]) {
        elements.standing.innerHTML = "";
        render({ ...statusHome("digest", "fresh"), digest: { chain_verified: true, chain_verdict: "verified", window_end } });
        expect.soft(elements.standing.innerHTML).toContain("not current");
        expect.soft(elements.standing.innerHTML).not.toContain("pill green");
      }

    } finally { vi.useRealTimers(); }
  });
});
