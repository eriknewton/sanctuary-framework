/**
 * Sanctuary v1.2.x Dashboard timeline per-action tick wiring.
 *
 * Asserts the embedded client script wires the existing
 * `renderActionAttestationBadge` helper into both the Agent detail
 * Timeline card and the Inspect panel recent activity timeline. Both
 * call sites must guard on the optional `attestation` field (absence
 * means the row renders without a badge), so that older feed payloads
 * that pre-date the schema extension keep rendering cleanly.
 *
 * Source-shape assertion only; the rendered DOM lives behind a real
 * SPA boot which is exercised by the broader dashboard surface tests.
 */

import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/index.js";

describe("v1.2.x dashboard timeline per-action attestation tick", () => {
  const client = getClientScript();

  it("Agent detail Timeline card guards on e.attestation and renders the badge", () => {
    const detailFn = client.match(
      /function renderAgentDetail\(\)[\s\S]*?\n\}\n/,
    );
    expect(detailFn).toBeTruthy();
    const body = detailFn![0];
    expect(body).toContain("e.attestation");
    expect(body).toContain("renderActionAttestationBadge(e.attestation.state, e.attestation.fragment)");
  });

  it("Inspect panel recent activity timeline guards on e.attestation and renders the badge", () => {
    const panelFn = client.match(
      /function renderAgentInspectPanel\(agent\)[\s\S]*?\n\}\n/,
    );
    expect(panelFn).toBeTruthy();
    const body = panelFn![0];
    expect(body).toContain("e.attestation");
    expect(body).toContain("renderActionAttestationBadge(e.attestation.state, e.attestation.fragment)");
    // Inspect panel wraps the badge in its own `<div class="att">` slot
    // so the existing `.timeline-item .att` CSS lays it out below `.what`.
    expect(body).toContain('<div class="att">');
  });

  it("the existing per-action badge helper is still present in the client script", () => {
    expect(client).toContain("function renderActionAttestationBadge(stateName, sig)");
    expect(client).toContain("att-action");
  });
});
