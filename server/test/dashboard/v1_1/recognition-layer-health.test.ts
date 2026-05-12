import { describe, expect, it } from "vitest";

import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

describe("v1.1 dashboard Recognition Layer health panel", () => {
  it("renders did:web health in the existing fortress-column sibling surface", () => {
    const src = getClientScript();
    expect(src).toContain("Recognition Layer health");
    expect(src).toContain("/recognition/did-web");
    expect(src).toContain("did-web-rotate-compromised");
    expect(src).not.toContain("dashboard-recognition-view");
  });

  it("keeps compromised rotation operator-driven through an explicit button action", () => {
    const src = getClientScript();
    expect(src).toContain("Compromised rotation");
    expect(src).toContain("onDidWebCompromisedRotation");
    expect(src).toContain("/recognition/did-web/rotate-compromised");
  });
});
