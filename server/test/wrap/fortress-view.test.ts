/**
 * Fortress View Tests
 *
 * Verifies the Fortress View HTML generation for the wrap dashboard.
 */

import { describe, it, expect } from "vitest";
import { generateFortressViewHTML } from "../../src/wrap/fortress-view.js";

describe("Fortress View", () => {
  it("generates valid HTML with version", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 3,
    });

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("<h1>Sanctuary</h1>");
    expect(html).toContain("0.7.0");
  });

  it("includes the status banner", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 2,
    });

    expect(html).toContain("status-banner");
    expect(html).toContain("2 servers monitored");
  });

  it("defaults the banner to amber 'enforcement not confirmed', NOT green 'protected' (never-overclaim)", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 2,
    });

    // The default/initial banner (before any Castle Wall posture evidence) must
    // be amber and must NOT claim protection or "All systems nominal".
    expect(html).toContain('<div class="status-indicator amber" id="status-indicator">');
    expect(html).toContain("Wrapped, enforcement not confirmed");
    // The legacy overclaiming default must be gone from the static banner.
    expect(html).not.toContain("All systems nominal");
  });

  it("only renders green 'Agent Protected' when Castle Wall posture is armed", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 2,
    });

    // Green is gated on the enforcement-evidenced arm state, consumed from the
    // G4 posture endpoint. The legitimate green path is preserved.
    expect(html).toContain("/api/posture/castle-wall");
    expect(html).toContain("arm_state");
    expect(html).toContain("wallArmState === 'armed'");
    // The green branch sets the protected copy and the enforcing subtitle.
    expect(html).toContain("Agent Protected");
    expect(html).toContain("Castle Wall enforcing.");
    // Green must be guarded by the armed check, not set unconditionally.
    expect(html).toContain("const wallArmed = wallArmState === 'armed'");
  });

  it("renders a red 'enforcement not active' banner when posture is degraded", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 2,
    });

    // A degraded wall (present but not enforcing) is a red, not-protected state.
    expect(html).toContain("wallArmState === 'degraded'");
    expect(html).toContain("Enforcement not active");
    expect(html).toContain("wrapped but not protected");
  });

  it("treats an unreachable posture endpoint as unproven, never protected", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 2,
    });

    // Posture fetch failure / non-OK falls back to an unproven (amber) state.
    expect(html).toContain("wallArmState = 'unavailable'");
    expect(html).toContain("Castle Wall enforcement not confirmed.");
  });

  it("handles singular server count", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 1,
    });

    expect(html).toContain("1 server monitored");
    expect(html).not.toContain("1 servers");
  });

  it("includes the live feed panel", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 1,
    });

    expect(html).toContain("Live Activity");
    expect(html).toContain("feed-list");
    expect(html).toContain("Waiting for tool calls...");
  });

  it("includes the alerts panel", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 1,
    });

    expect(html).toContain("Needs Attention");
    expect(html).toContain("alerts-list");
    expect(html).toContain("No pending actions");
  });

  it("includes the upstream servers panel", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 1,
    });

    expect(html).toContain("Upstream Servers");
    expect(html).toContain("servers-list");
  });

  it("does not render non-enforcing pause controls", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 1,
    });

    expect(html).not.toContain("Pause Agent");
    expect(html).not.toContain("pause-btn");
    expect(html).not.toContain("/api/cocoon/pause");
  });

  it("includes SSE connection for proxy-call events", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 1,
    });

    expect(html).toContain("proxy-call");
    expect(html).toContain("EventSource");
  });

  it("includes approval handling JavaScript", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 1,
    });

    expect(html).toContain("handleApproval");
    expect(html).toContain("/api/approve/");
    expect(html).toContain("/api/deny/");
  });

  it("escapes HTML in version string", () => {
    const html = generateFortressViewHTML({
      serverVersion: "<script>alert(1)</script>",
      upstreamServerCount: 1,
    });

    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("includes stat counters", () => {
    const html = generateFortressViewHTML({
      serverVersion: "0.7.0",
      upstreamServerCount: 1,
    });

    expect(html).toContain("stat-total");
    expect(html).toContain("stat-blocked");
    expect(html).toContain("stat-pending");
    expect(html).toContain("Calls");
    expect(html).toContain("Blocked");
    expect(html).toContain("Pending");
  });
});
