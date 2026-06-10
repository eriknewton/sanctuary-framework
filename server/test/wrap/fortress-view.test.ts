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
    expect(html).toContain("Agent Protected");
    expect(html).toContain("2 servers monitored");
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
