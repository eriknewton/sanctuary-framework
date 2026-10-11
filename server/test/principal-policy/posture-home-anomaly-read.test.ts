import { describe, expect, it } from "vitest";

import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";

type AnomalyHarness = {
  renderAnomalies: (input: unknown) => void;
  anomaliesEl: { innerHTML: string };
};

function anomalyHarness(): AnomalyHarness {
  const html = renderPostureHomeHTML();
  const escStart = html.indexOf("function esc(s)");
  const escEnd = html.indexOf('  // "Never fake green": ARMED');
  const anomalyStart = html.indexOf("function renderAnomalies(findings)");
  const anomalyEnd = html.indexOf('  // "Never fake green" for the fleet roster.');
  expect(escStart).toBeGreaterThan(-1);
  expect(escEnd).toBeGreaterThan(escStart);
  expect(anomalyStart).toBeGreaterThan(-1);
  expect(anomalyEnd).toBeGreaterThan(anomalyStart);

  const anomaliesEl = { innerHTML: "" };
  const document = {
    getElementById(id: string) {
      if (id === "anomalies") return anomaliesEl;
      return null;
    },
  };
  const source =
    html.slice(escStart, escEnd) +
    "\n" +
    html.slice(anomalyStart, anomalyEnd) +
    "\nreturn { renderAnomalies: renderAnomalies };";
  const helpers = new Function("document", source)(document) as Pick<
    AnomalyHarness,
    "renderAnomalies"
  >;
  return { ...helpers, anomaliesEl };
}

describe("posture home anomaly read outcome", () => {
  it("renders an unavailable detector read distinctly from a verified empty answer", () => {
    const h = anomalyHarness();

    h.renderAnomalies({ status: "unavailable", findings: [] });

    expect(h.anomaliesEl.innerHTML).toContain("Anomaly detector unavailable.");
    expect(h.anomaliesEl.innerHTML).toContain("pill amber");
    expect(h.anomaliesEl.innerHTML).not.toContain(
      "The detector answered and reported nothing open.",
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
