import { describe, expect, it } from "vitest";
import {
  custodyPill,
  featureHealthPill,
  renderPostureHomeHTML,
} from "../../src/principal-policy/posture-home-html.js";
import type { FeatureHealthStatus } from "../../src/principal-policy/feature-health.js";
import type { CustodyState } from "../../src/principal-policy/posture.js";

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

/**
 * Slice 3 of the unified posture dashboard: the Custody and Exit panel. These
 * tests pin the #617 honesty contract on the new tile — custody is GREEN NEVER
 * (custody HEALTH lives under the transient master at boot and is not
 * re-derivable from the dashboard's request-time view), so "unconfirmed" is
 * amber and "damaged" is red, with no green branch. The exit half is the honest
 * CLI-gated export capability with NO clean-exit guarantee claimed.
 */
describe("posture home — Custody and Exit panel honesty", () => {
  it("custodyPill: there is no green branch — unconfirmed is amber, damaged is red", () => {
    expect(custodyPill("unconfirmed").cls).toBe("amber");
    expect(custodyPill("damaged").cls).toBe("red");
    // Neither state may ever map to a green class.
    const states: CustodyState[] = ["unconfirmed", "damaged"];
    for (const s of states) {
      expect(custodyPill(s).cls).not.toBe("green");
    }
  });

  it("renders a Custody and Exit section on the Home page", () => {
    const html = renderPostureHomeHTML();
    expect(html).toContain("Custody and Exit");
    expect(html).toContain('id="custody"');
    // Fed from the home payload's already-built custody-exit panel (no duplicate
    // endpoint logic on the surface).
    expect(html).toContain("renderCustodyExit(home.custody_exit)");
  });

  it("the client-side custody renderer never maps any state to a green pill", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function custodyPill(state)");
    expect(start).toBeGreaterThan(-1);
    const fnSource = html.slice(start, start + 300);
    // damaged -> red; the default (unconfirmed) -> amber. No green anywhere.
    expect(fnSource).toContain('state === "damaged") return \'<span class="pill red">');
    expect(fnSource).toContain('<span class="pill amber">UNCONFIRMED');
    expect(fnSource).not.toContain("pill green");
  });

  it("surfaces the exit export as a capability WITHOUT claiming a clean-exit guarantee", () => {
    const html = renderPostureHomeHTML();
    // The honest exit affordance: export available, Tier-1 gated. The command
    // string is sourced from the panel at render time; the renderer falls back
    // to the literal `sanctuary exit` verb, which is therefore present statically.
    expect(html).toContain("export available");
    expect(html).toContain("sanctuary exit");
    // It is a Tier-1 (approval-gated) operation, surfaced honestly.
    expect(html).toContain("a Tier-1 operation");
    // And the explicit honesty disclaimer that the full clean-exit guarantee is
    // NOT yet earned (delta review). No "clean exit guaranteed" claim on Home.
    expect(html).toContain("does not yet mean a guaranteed clean exit");
    expect(html.toLowerCase()).not.toContain("clean exit guaranteed");
  });

  it("uses no em-dashes in the rendered Custody and Exit user-facing copy", () => {
    const html = renderPostureHomeHTML();
    // Isolate the custody renderer's user-facing strings region.
    const start = html.indexOf("function renderCustodyExit(panel)");
    const end = html.indexOf("function renderBanner(home");
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const region = html.slice(start, end);
    expect(region).not.toContain("—"); // em-dash
  });
});
