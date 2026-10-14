import { describe, expect, it } from "vitest";

import { generateFleetSwitcherHTML } from "../../src/principal-policy/dashboard-html.js";

function fleetSwitcherHTML(): string {
  return generateFleetSwitcherHTML({
    serverVersion: "9.9.9-test",
    protocol: "http",
    currentHost: "127.0.0.1",
    currentPort: 3501,
  });
}

function fleetSwitcherScript(): string {
  const html = fleetSwitcherHTML();
  const match = html.match(/<script>\s*const STORAGE_KEY[\s\S]*?<\/script>/);
  expect(match).not.toBeNull();
  return match![0];
}

describe("fleet switcher saved-card rendering", () => {
  it("keeps saved-entry fields out of generated markup and script templates", () => {
    const html = fleetSwitcherHTML();
    const script = fleetSwitcherScript();

    expect(script).not.toContain("${");
    expect(html.toLowerCase()).not.toContain("onclick=");

    const innerHTMLAssignments = Array.from(
      script.matchAll(/\.innerHTML\s*=\s*([^;]+);/g),
      (match) => match[1].trim(),
    );
    expect(innerHTMLAssignments.length).toBeGreaterThan(0);
    for (const rightSide of innerHTMLAssignments) {
      expect(rightSide).toMatch(/^(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")$/);
    }
  });
});
