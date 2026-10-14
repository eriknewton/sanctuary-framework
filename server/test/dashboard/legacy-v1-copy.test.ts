import { describe, expect, it } from "vitest";
import { getProtectionSnapshot } from "../../src/dashboard/aggregator.js";
import { renderDashboardHTML } from "../../src/dashboard/html.js";

describe("legacy v1.0 dashboard copy", () => {
  it("renders the real aggregator strings with canonical layer names and no em dash", async () => {
    const snapshot = await getProtectionSnapshot({
      mode: "standalone",
      server_version: "copy-sweep-test",
    });
    const html = renderDashboardHTML({ snapshot });

    expect(html).toContain("Castle Wall");
    expect(html).toContain("Sentinels");
    expect(html).toContain("Charter");
    expect(html).toContain("Heralds");
    expect(html).not.toContain("L1 Cognitive");
    expect(html).not.toContain("L2 Operational");
    expect(html).not.toContain("L3 Disclosure");
    expect(html).not.toContain("L4 Reputation");
    expect(html).not.toContain("\u2014");
    expect(html).not.toContain("&mdash;");
  });
});
