import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { getProtectionSnapshot } from "../../src/dashboard/aggregator.js";
import { renderDashboardHTML } from "../../src/dashboard/html.js";
import { renderPostureAgentHTML } from "../../src/principal-policy/posture-agent-html.js";
import { renderPostureEvidenceHTML } from "../../src/principal-policy/posture-evidence-html.js";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";

function inlineScripts(html: string): string[] {
  return [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\b[^>]*>/gi)]
    .map((match) => match[1] ?? "");
}

describe("legacy page inline scripts parse", () => {
  it("parses every inline script emitted by the legacy dashboard and posture pages", async () => {
    const snapshot = await getProtectionSnapshot({
      mode: "standalone",
      server_version: "script-parse-test",
    });
    snapshot.audit = [
      {
        timestamp: new Date(Date.UTC(2026, 9, 14, 12)).toISOString(),
        layer: "l1",
        operation: "identity_create",
        identity_id: "id-1",
        result: "success",
      },
    ];
    const pages = {
      "posture agent": renderPostureAgentHTML(),
      "posture home": renderPostureHomeHTML(),
      "posture evidence": renderPostureEvidenceHTML(),
      "dashboard v1.0": renderDashboardHTML({ snapshot }),
    };

    for (const [name, html] of Object.entries(pages)) {
      const scripts = inlineScripts(html);
      expect(scripts.length, name).toBeGreaterThan(0);
      scripts.forEach((body, index) => {
        expect(() => new vm.Script(body), `${name} script ${index}`).not.toThrow();
      });
    }
  });
});
