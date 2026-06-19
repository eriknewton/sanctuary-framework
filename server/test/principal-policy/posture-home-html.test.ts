import { describe, expect, it } from "vitest";
import {
  featureHealthPill,
  renderPostureHomeHTML,
} from "../../src/principal-policy/posture-home-html.js";
import type { FeatureHealthStatus } from "../../src/principal-policy/feature-health.js";

/**
 * Slice 2 of the unified posture dashboard: the feature-health panel is now
 * rendered on Home. These tests pin the #617/#634 honesty contract on the new
 * panel — an "unknown"/"unconfirmed" feature must NEVER render green; green is
 * earned only by "active"; "fault" is red. The contract is enforced both by the
 * pure exported mapper (the canonical definition) and inside the self-contained
 * client-side renderer string (which mirrors it).
 */
describe("posture home — feature-health panel honesty", () => {
  it("featureHealthPill: an unknown/unconfirmed feature never renders green", () => {
    expect(featureHealthPill("unknown").cls).toBe("amber");
    expect(featureHealthPill("unconfirmed").cls).toBe("amber");
    // Neither non-green status may map to the single green class.
    expect(featureHealthPill("unknown").cls).not.toBe("green");
    expect(featureHealthPill("unconfirmed").cls).not.toBe("green");
  });

  it("featureHealthPill: a known-good (active) feature renders its positive green chip", () => {
    const pill = featureHealthPill("active");
    expect(pill.cls).toBe("green");
    expect(pill.label).toBe("active");
  });

  it("featureHealthPill: a fault renders red, never green", () => {
    expect(featureHealthPill("fault").cls).toBe("red");
    expect(featureHealthPill("fault").cls).not.toBe("green");
  });

  it("featureHealthPill: green is reserved exclusively for active across every status", () => {
    const statuses: FeatureHealthStatus[] = [
      "active",
      "fault",
      "unconfirmed",
      "unknown",
    ];
    for (const s of statuses) {
      const isGreen = featureHealthPill(s).cls === "green";
      expect(isGreen).toBe(s === "active");
    }
  });

  it("renders a Security features section on the Home page", () => {
    const html = renderPostureHomeHTML();
    expect(html).toContain("Security features");
    expect(html).toContain('id="features"');
    // The panel is fed from the home payload's already-built feature-health
    // panel (no duplicate endpoint logic on the surface).
    expect(html).toContain("renderFeatures(home.feature_health)");
  });

  it("the client-side feature renderer never maps a non-active status to a green pill", () => {
    const html = renderPostureHomeHTML();
    // Isolate the embedded featurePill function source and assert its honest
    // mapping: only "active" produces a green pill; unconfirmed/unknown are amber.
    const start = html.indexOf("function featurePill(status)");
    expect(start).toBeGreaterThan(-1);
    const fnSource = html.slice(start, start + 400);
    expect(fnSource).toContain('status === "active") return \'<span class="pill green">');
    // No green branch keyed on unconfirmed or unknown.
    expect(fnSource).not.toMatch(/unconfirmed[^\n]*pill green/);
    expect(fnSource).not.toMatch(/unknown[^\n]*pill green/);
    expect(fnSource).toContain('unconfirmed") return \'<span class="pill amber">');
  });
});
