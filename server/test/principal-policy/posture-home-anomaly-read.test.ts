import { describe, expect, it } from "vitest";

import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";

type AnomalyHarness = {
  renderAnomalies: (input: unknown) => void;
  renderBanner: (home: unknown, approvals: unknown, anomalies: unknown) => void;
  refreshAuxiliary: () => Promise<void>;
  lastFindings: () => unknown;
  anomaliesEl: { innerHTML: string };
  bannerEl: { innerHTML: string };
};

function anomalyHarness(responses: Record<string, unknown> = {}): AnomalyHarness {
  const html = renderPostureHomeHTML();
  const bannerStart = html.indexOf("function renderBanner(home, approvalState, anomalies)");
  const bannerEnd = html.indexOf("  // F2 BLOCKER-1: three-state pill");
  const anomalyStart = html.indexOf("function renderAnomalies(findings)");
  const anomalyEnd = html.indexOf('  // "Never fake green" for the fleet roster.');
  const auxiliaryStart = html.indexOf("  var lastApprovals =");
  const auxiliaryEnd = html.indexOf("  // Apply a fresh home payload");
  expect(bannerStart).toBeGreaterThan(-1);
  expect(bannerEnd).toBeGreaterThan(bannerStart);
  expect(anomalyStart).toBeGreaterThan(-1);
  expect(anomalyEnd).toBeGreaterThan(anomalyStart);
  expect(auxiliaryStart).toBeGreaterThan(-1);
  expect(auxiliaryEnd).toBeGreaterThan(auxiliaryStart);

  const anomaliesEl = { innerHTML: "" };
  const bannerEl = { innerHTML: "" };
  const document = {
    getElementById(id: string) {
      if (id === "anomalies") return anomaliesEl;
      if (id === "banner") return bannerEl;
      if (id === "origin") return { textContent: "" };
      return null;
    },
  };
  const api = (path: string) => Promise.resolve(responses[path] ?? []);
  const source =
    `
function esc(s) { return String(s == null ? "" : s); }
function stat(value, label) { return '<span data-label="' + label + '">' + value + '</span>'; }
function wallPill() { return '<span>wall</span>'; }
function auditChainPill() { return '<span>audit</span>'; }
function approvalsWaitingValue() { return 0; }
function buildApprovalState() { return { rows: [], can_decide: false, mode: "unknown", source: "none" }; }
` +
    html.slice(bannerStart, bannerEnd) +
    "\n" +
    html.slice(anomalyStart, anomalyEnd) +
    "\n" +
    html.slice(auxiliaryStart, auxiliaryEnd) +
    "\nreturn { renderAnomalies: renderAnomalies, renderBanner: renderBanner, refreshAuxiliary: refreshAuxiliary, lastFindings: function () { return lastFindings; } };";
  const helpers = new Function("document", "api", source)(document, api) as Pick<
    AnomalyHarness,
    "renderAnomalies" | "renderBanner" | "refreshAuxiliary" | "lastFindings"
  >;
  return { ...helpers, anomaliesEl, bannerEl };
}

describe("posture home anomaly read outcome", () => {
  const routeEnvelopeWithFinding = {
    ok: true,
    data: {
      findings: [
        {
          severity: "high",
          summary: "Open anomaly finding from the detector",
        },
      ],
    },
  };

  const minimalHome = {
    origin_machine: "local",
    agents: [],
    unwrapped: { unwrapped: [] },
    protection_requested_count: 0,
    enforcement_confirmed_count: 0,
    castle_wall: { arm_state: "unknown" },
    digest: {},
  };

  it("renders an unavailable detector read distinctly from a verified empty answer", () => {
    const h = anomalyHarness();

    h.renderAnomalies({ status: "unavailable", findings: [] });

    expect(h.anomaliesEl.innerHTML).toContain("Anomaly detector unavailable.");
    expect(h.anomaliesEl.innerHTML).toContain("pill amber");
    expect(h.anomaliesEl.innerHTML).not.toContain(
      "The detector answered and reported nothing open.",
    );
  });

  it("renders the real findings envelope without treating it as verified empty", async () => {
    const h = anomalyHarness({
      "/api/anomaly/findings": routeEnvelopeWithFinding,
    });

    await h.refreshAuxiliary();
    h.renderAnomalies(h.lastFindings());

    expect(h.anomaliesEl.innerHTML).toContain(
      "Open anomaly finding from the detector",
    );
    expect(h.anomaliesEl.innerHTML).not.toContain(
      "The detector answered and reported nothing open.",
    );
  });

  it("does not render a confident zero when the detector read is unavailable", () => {
    const h = anomalyHarness();

    h.renderBanner(minimalHome, {}, { status: "unavailable", findings: [] });

    expect(h.bannerEl.innerHTML).toContain("UNAVAILABLE");
    expect(h.bannerEl.innerHTML).not.toContain(
      'data-label="Open anomalies">0</span>',
    );
  });

  it("keeps the auxiliary read failure distinct from zero findings", () => {
    const html = renderPostureHomeHTML();

    expect(html).not.toContain(
      'api("/api/anomaly/findings").catch(function () { return { findings: [] }; })',
    );
    expect(html).toContain('status: "unavailable"');
  });
});
