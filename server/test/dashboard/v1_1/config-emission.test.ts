/**
 * Sanctuary v1.1 Dashboard — `<script id="dashboard-config">` emission.
 *
 * Regression suite for Finding Y (drill-arrest 2026-04-27 AM). Y closed
 * in v1.1.4 by emitting raw JSON inside the `<script type="application/json">`
 * block instead of HTML-escaping it; the previous shape produced `&quot;`
 * inside RAWTEXT, breaking the client's `JSON.parse(cfgEl.textContent)`.
 *
 * Tests assert against the renderer (`renderDashboardV11Html`) directly.
 * The route handler at `server/src/dashboard/v1_1/routes.ts` is a
 * pass-through (`res.end(renderDashboardV11Html(deps))`) so renderer
 * coverage equals served-HTML coverage. No headless-browser dependency.
 */

import { describe, expect, it } from "vitest";
import { renderDashboardV11Html } from "../../../src/dashboard/v1_1/index.js";

function extractConfigBlock(html: string): string {
  const match = html.match(
    /<script id="dashboard-config" type="application\/json">([\s\S]*?)<\/script>/,
  );
  expect(match, "dashboard-config script block not found in rendered HTML")
    .not.toBeNull();
  return (match as RegExpMatchArray)[1];
}

describe("v1.1 dashboard config emission (Finding Y regression)", () => {
  it("emits a JSON-parseable config block (no HTML entity encoding)", () => {
    const html = renderDashboardV11Html({
      authToken: "tkn-abc-123",
      hubApiBase: "/api/hub",
      streamUrl: "/api/stream",
      identityId: "fortress:/Users/test/.sanctuary",
      fortressId: "fortress-deadbeef",
    });
    const inner = extractConfigBlock(html);
    expect(() => JSON.parse(inner)).not.toThrow();
  });

  it("parsed config carries the five expected keys with original values", () => {
    const html = renderDashboardV11Html({
      authToken: "tkn-abc-123",
      hubApiBase: "/api/hub",
      streamUrl: "/api/stream",
      identityId: "operator-007",
      fortressId: "fortress-007",
    });
    const inner = extractConfigBlock(html);
    const parsed = JSON.parse(inner) as Record<string, string>;
    expect(parsed.authToken).toBe("tkn-abc-123");
    expect(parsed.hubApiBase).toBe("/api/hub");
    expect(parsed.streamUrl).toBe("/api/stream");
    expect(parsed.identityId).toBe("operator-007");
    expect(parsed.fortressId).toBe("fortress-007");
  });

  it("config block contains literal quote characters, not HTML entities (locks in fix)", () => {
    const html = renderDashboardV11Html({
      authToken: "tkn-xyz",
      identityId: "operator",
      fortressId: "fortress",
    });
    const inner = extractConfigBlock(html);
    // Negative assertion: the v1.1.3 broken shape produced `&quot;`.
    expect(inner).not.toContain("&quot;");
    // Positive assertion: literal double quotes around JSON keys.
    expect(inner).toContain('"authToken"');
    expect(inner).toContain('"fortressId"');
  });

  it("unicode-escapes `<` so a config value cannot close the script block", () => {
    // A config value containing `</script>` would close the RAWTEXT block
    // early and break parsing. Unicode-escaping `<` to `<` blocks
    // that path regardless of caller-provided value content.
    const html = renderDashboardV11Html({
      authToken: "tkn",
      identityId: "</script><img src=x onerror=alert(1)>",
      fortressId: "fortress",
    });
    const inner = extractConfigBlock(html);
    // The dangerous literal substring must NOT appear inside the script
    // block.
    expect(inner).not.toContain("</script>");
    // The unicode-escape form is what JSON.parse decodes back to `<`.
    expect(inner).toContain("\\u003c");
    // Round-trip: the parsed value still equals the original input
    // (JSON.parse decodes `<` back to `<`).
    const parsed = JSON.parse(inner) as { identityId: string };
    expect(parsed.identityId).toBe(
      "</script><img src=x onerror=alert(1)>",
    );
  });

  it("handles default option fallbacks (no caller-provided fields)", () => {
    const html = renderDashboardV11Html();
    const inner = extractConfigBlock(html);
    expect(() => JSON.parse(inner)).not.toThrow();
    const parsed = JSON.parse(inner) as Record<string, string>;
    expect(parsed.authToken).toBe("");
    expect(parsed.hubApiBase).toBe("/api/hub");
    expect(parsed.streamUrl).toBe("/api/stream");
    expect(parsed.identityId).toBe("operator");
    expect(parsed.fortressId).toBe("fortress");
  });
});
