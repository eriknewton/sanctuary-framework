/**
 * Tenant naming consistency test (BBBB)
 *
 * Verifies that the dashboard surfaces the same tenant name as the CLI
 * by checking:
 *   1. The HTML shell renders tenantName in the topbar when provided.
 *   2. The client script renders tenantName in the fortress card.
 *   3. The HTML shell topbar shows only fortressId when tenantName is absent.
 */

import { describe, it, expect } from "vitest";
import { getClientScript } from "../../src/dashboard/v1_1/client.js";
import { renderDashboardV11Html } from "../../src/dashboard/v1_1/html.js";

describe("Tenant naming consistency (BBBB)", () => {
  it("topbar renders tenantName alongside fortressId when provided", () => {
    const html = renderDashboardV11Html({
      sanctuaryVersion: "1.3.0-test",
      fortressId: "fortress-abc123",
      tenantName: "default",
      embedClient: false,
    });
    expect(html).toContain("default fortress-abc123");
  });

  it("topbar renders only fortressId when tenantName is absent", () => {
    const html = renderDashboardV11Html({
      sanctuaryVersion: "1.3.0-test",
      fortressId: "fortress-abc123",
      embedClient: false,
    });
    // Should just show fortress ID, no leading space
    expect(html).toContain(">fortress-abc123<");
    expect(html).not.toContain("default fortress-abc123");
  });

  it("client script renders tenantName in fortress card", () => {
    const script = getClientScript();
    expect(script).toContain("config.tenantName");
  });

  it("config JSON includes tenantName field", () => {
    const html = renderDashboardV11Html({
      sanctuaryVersion: "1.3.0-test",
      fortressId: "fortress-abc123",
      tenantName: "my-fortress",
      embedClient: false,
    });
    expect(html).toContain('"tenantName"');
    expect(html).toContain("my-fortress");
  });
});
