import { describe, expect, it } from "vitest";
import { getProtectionSnapshot } from "../../src/dashboard/aggregator.js";
import { renderDashboardHTML } from "../../src/dashboard/html.js";
import type { ProtectionSnapshot } from "../../src/dashboard/aggregator.js";

const LAYER_ENTRIES = [
  { layer: "l1", operation: "identity_create" },
  { layer: "l2", operation: "gate_allow" },
  { layer: "l3", operation: "proof_reveal" },
  { layer: "l4", operation: "reputation_record" },
] as const;

function visibleText(html: string): string {
  return html
    .replace(/<script\b[\s\S]*?<\/script\b[^>]*>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style\b[^>]*>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function snapshotWithAudit(snapshot: ProtectionSnapshot): ProtectionSnapshot {
  return {
    ...snapshot,
    audit: LAYER_ENTRIES.map((entry, i) => ({
      timestamp: new Date(Date.UTC(2026, 9, 14, 12, i)).toISOString(),
      layer: entry.layer,
      operation: entry.operation,
      identity_id: `id-${entry.layer}`,
      result: "success",
    })),
  };
}

function clientRenderAudit(html: string, entries: ProtectionSnapshot["audit"]): string {
  const start = html.indexOf("function esc(value)");
  const end = html.indexOf("function renderPrivacy(summary)");
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  const bodyEl = { innerHTML: "" };
  const countEl = { textContent: "" };
  const activeFilter = { dataset: { filter: "all" } };
  const document = {
    getElementById: (id: string) =>
      id === "audit-body" ? bodyEl :
      id === "audit-count" ? countEl :
      null,
    querySelector: (selector: string) =>
      selector === "#audit-filter button.active" ? activeFilter : null,
  };
  const source = `${html.slice(start, end)}
renderAudit(entries, "all");
return bodyEl.innerHTML;`;
  // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
  return new Function("document", "entries", "bodyEl", source)(document, entries, bodyEl) as string;
}

describe("legacy v1.0 dashboard copy", () => {
  it("renders the real aggregator strings with Health Score layer names and no em dash", async () => {
    const snapshot = await getProtectionSnapshot({
      mode: "standalone",
      server_version: "copy-sweep-test",
    });
    const html = renderDashboardHTML({ snapshot });

    expect(html).toContain("Cognitive");
    expect(html).toContain("Operational");
    expect(html).toContain("Selective Disclosure");
    expect(html).toContain("Verifiable Reputation");
    expect(html).toContain("No identity yet. Run sanctuary_bootstrap");
    expect(html).not.toContain("No protected identity yet");
    expect(html).not.toContain("L1 Cognitive");
    expect(html).not.toContain("L2 Operational");
    expect(html).not.toContain("L3 Disclosure");
    expect(html).not.toContain("L4 Reputation");
    expect(html).not.toContain("\u2014");
    expect(html).not.toContain("&mdash;");
  });

  it("renders one audit entry per legacy layer by name on server and client paths", async () => {
    const snapshot = snapshotWithAudit(await getProtectionSnapshot({
      mode: "standalone",
      server_version: "copy-sweep-test",
    }));
    const html = renderDashboardHTML({ snapshot });

    for (const name of ["Cognitive", "Operational", "Selective Disclosure", "Verifiable Reputation"]) {
      expect(html).toContain(`>${name}</span>`);
    }
    expect(visibleText(html)).not.toMatch(/\bL[1-4]\b/i);

    const clientRows = clientRenderAudit(html, snapshot.audit);
    for (const name of ["Cognitive", "Operational", "Selective Disclosure", "Verifiable Reputation"]) {
      expect(clientRows).toContain(`>${name}</span>`);
    }
    expect(visibleText(clientRows)).not.toMatch(/\bL[1-4]\b/i);
  });

  it("falls back to an escaped neutral pill for an unknown audit layer token", async () => {
    const snapshot = snapshotWithAudit(await getProtectionSnapshot({
      mode: "standalone",
      server_version: "copy-sweep-test",
    }));
    snapshot.audit = [{
      timestamp: new Date(Date.UTC(2026, 9, 14, 12)).toISOString(),
      layer: "lx" as ProtectionSnapshot["audit"][number]["layer"],
      operation: "custom_op",
      identity_id: "id-x",
      result: "success",
    }];
    const html = renderDashboardHTML({ snapshot });

    expect(html).toContain('class="layer-pill neutral" title="lx">lx</span>');
    expect(html).not.toContain(">undefined</span>");
  });
});
