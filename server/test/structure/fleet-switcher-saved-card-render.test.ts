import { describe, expect, it } from "vitest";

import { generateFleetSwitcherHTML } from "../../src/principal-policy/dashboard-html.js";

function fleetSwitcherScript(): string {
  const html = generateFleetSwitcherHTML({
    serverVersion: "9.9.9-test",
    protocol: "http",
    currentHost: "127.0.0.1",
    currentPort: 3501,
  });
  const match = html.match(/<script>\s*const STORAGE_KEY[\s\S]*?<\/script>/);
  expect(match).not.toBeNull();
  return match![0];
}

function fleetSwitcherRenderFunction(script: string): string {
  const start = script.indexOf("function render()");
  expect(start).toBeGreaterThanOrEqual(0);
  const escapeHelper = script.indexOf("function escapeHtml", start);
  const autoAdd = script.indexOf("// Auto-add current machine", start);
  const end = escapeHelper === -1 ? autoAdd : escapeHelper;
  expect(end).toBeGreaterThan(start);
  return script.slice(start, end);
}

describe("fleet switcher saved-card rendering", () => {
  it("keeps saved-entry fields out of markup templates and inline click attributes", () => {
    const script = fleetSwitcherScript();
    const renderFunction = fleetSwitcherRenderFunction(script);

    expect(renderFunction).not.toMatch(/\.innerHTML\s*=[\s\S]*\$\{/);
    expect(script).not.toContain("onclick=");
  });
});
