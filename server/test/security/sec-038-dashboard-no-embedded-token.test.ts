/**
 * SEC-038: Dashboard HTML must not embed the long-lived auth token.
 *
 * The auth token should only be stored in sessionStorage by the login flow,
 * never embedded as a JavaScript literal in the page source.
 */

import { describe, it, expect } from "vitest";
import { generateDashboardHTML } from "../../src/principal-policy/dashboard-html.js";

describe("SEC-038: Dashboard HTML does not embed auth token", () => {
  const testToken = "test-secret-token-abc123def456";

  it("does not embed the auth token as a JavaScript literal", () => {
    const html = generateDashboardHTML({
      timeoutSeconds: 300,
      serverVersion: "0.5.11",
      authToken: testToken,
    });

    // The token should NOT appear anywhere in the HTML
    expect(html).not.toContain(testToken);
  });

  it("uses sessionStorage.getItem for auth token", () => {
    const html = generateDashboardHTML({
      timeoutSeconds: 300,
      serverVersion: "0.5.11",
      authToken: testToken,
    });

    // The HTML should use sessionStorage to get the token
    expect(html).toContain("sessionStorage.getItem('authToken')");
  });

  it("does not contain template interpolation of authToken", () => {
    const html = generateDashboardHTML({
      timeoutSeconds: 300,
      serverVersion: "0.5.11",
      authToken: "some-other-token",
    });

    // Should not have the old pattern: '${options.authToken}'
    expect(html).not.toContain("some-other-token");
  });
});
