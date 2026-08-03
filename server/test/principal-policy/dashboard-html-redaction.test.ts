import { describe, expect, it } from "vitest";
import { generateDashboardHTML } from "../../src/principal-policy/dashboard-html.js";

describe("principal dashboard pending approval redaction client", () => {
  it("renders a hidden-not-empty pending state for redacted /events approval markers", () => {
    const html = generateDashboardHTML({
      timeoutSeconds: 30,
      serverVersion: "test",
      loopbackAutoAuth: true,
    });

    expect(html).toContain("isPendingApprovalsRedactedMarker");
    expect(html).toContain("pendingRequestsRedacted");
    expect(html).toContain("Approvals are hidden, not empty.");
    expect(html).toContain("pending_approvals_count");
  });
});
