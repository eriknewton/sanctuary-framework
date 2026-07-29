/**
 * Tenant naming consistency test (BBBB)
 *
 * Verifies that the dashboard surfaces the same tenant name as the CLI
 * by checking:
 *   1. The HTML shell renders tenantName in the topbar when provided.
 *   2. The client script renders tenantName in the fortress card.
 *   3. The HTML shell topbar shows the fortressId chip when tenantName is absent.
 *
 * S2 (2026-07-18): the top bar no longer concatenates "tenant fortressId" in a
 * single .brand span. The machine alias (tenantName, human name) now leads in a
 * .machine-name span and the raw fortressId is demoted to a copyable .idchip.
 */

import { describe, it, expect } from "vitest";
import { getClientScript } from "../../src/dashboard/v1_1/client.js";
import { renderDashboardV11Html } from "../../src/dashboard/v1_1/html.js";

describe("Tenant naming consistency (BBBB)", () => {
  it("topbar renders the tenant alias and the fortressId chip when tenant provided", () => {
    const html = renderDashboardV11Html({
      sanctuaryVersion: "1.3.0-test",
      fortressId: "fortress-abc123",
      tenantName: "default",
      embedClient: false,
    });
    // Human alias leads (the same name the CLI shows); the raw id is a chip.
    expect(html).toContain('class="machine-name">default<');
    expect(html).toContain('data-fortress-id="fortress-abc123"');
    expect(html).toContain(">fortress-abc123<");
  });

  it("topbar falls back to a generic alias and still shows the fortressId chip when tenant absent", () => {
    const html = renderDashboardV11Html({
      sanctuaryVersion: "1.3.0-test",
      fortressId: "fortress-abc123",
      embedClient: false,
    });
    // No tenant name to show, so the alias is a generic label; the id chip
    // still carries the fortressId verbatim for copy.
    expect(html).toContain('class="machine-name">This machine<');
    expect(html).toContain(">fortress-abc123<");
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
