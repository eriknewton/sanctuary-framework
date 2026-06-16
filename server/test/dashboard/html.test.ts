/**
 * Dashboard HTML rendering tests — verifies the hero shield, the four
 * layer cards, hero copy, activity table, approval list, and audit
 * filters all render from a given snapshot.
 */

import { describe, it, expect } from "vitest";
import { renderDashboardHTML, HERO_COPY } from "../../src/dashboard/html.js";
import type { ProtectionSnapshot } from "../../src/dashboard/aggregator.js";

function makeSnapshot(overrides: Partial<ProtectionSnapshot> = {}): ProtectionSnapshot {
  const base: ProtectionSnapshot = {
    overall: { status: "healthy", light: "green", headline: "All layers full" },
    agent: {
      display_name: "Test Agent",
      did: "did:key:z6MkAbcDefGhi123456",
      did_fingerprint: "z6MkAb…123456",
      identity_count: 1,
      primary_identity_id: "id-1",
    },
    layers: {
      l1: {
        label: "L1 Cognitive",
        state: "full",
        headline: "State encrypted at rest",
        encryption: "AES-256-GCM",
        injection_blocked_today: 2,
        memory_attest_ready: true,
      },
      l2: {
        label: "L2 Operational",
        state: "degraded",
        headline: "Process isolation — no TEE on this host",
        isolation_type: "process-level",
        tee_available: false,
        tee_status: "Not available — normal on local dev",
        sandbox_status: "Principal Policy gate active",
      },
      l3: {
        label: "L3 Disclosure",
        state: "full",
        headline: "Selective disclosure ready",
        did_active: true,
        vc_count: 3,
        proofs_today: 1,
      },
      l4: {
        label: "L4 Reputation",
        state: "full",
        headline: "Verascore attached",
        score: 82,
        profile_url: "https://verascore.ai/p/test",
        claim_cta: null,
      },
    },
    activity: [
      {
        timestamp: new Date().toISOString(),
        tool: "state_write",
        server: "sanctuary",
        tier: 3,
        result: "allowed",
      },
    ],
    pending_approvals: [
      {
        id: "req-1",
        operation: "state_export",
        tier: 1,
        reason: "Tier 1 export requires approval",
        created_at: new Date().toISOString(),
      },
    ],
    audit: [
      {
        timestamp: new Date().toISOString(),
        layer: "l1",
        operation: "identity_create",
        identity_id: "id-1",
        result: "success",
      },
    ],
    privacy: {
      filtered_events: 1,
      filtered_spans: 2,
      classes: { email: 1, phone: 1 },
      last_filtered_at: new Date().toISOString(),
    },
    upstream_servers: [
      { name: "filesystem", state: "connected", tool_count: 5 },
    ],
    mode: "co-located",
    server_version: "0.9.0-test",
    generated_at: new Date().toISOString(),
  };
  return { ...base, ...overrides };
}

describe("renderDashboardHTML", () => {
  it("renders all four layer cards with their labels", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain("L1 Cognitive");
    expect(html).toContain("L2 Operational");
    expect(html).toContain("L3 Disclosure");
    expect(html).toContain("L4 Reputation");
  });

  it("applies the correct shield color class for green status", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toMatch(/class="shield green"/);
  });

  it("applies the correct shield color class for yellow status", () => {
    const html = renderDashboardHTML({
      snapshot: makeSnapshot({
        overall: { status: "degraded", light: "yellow", headline: "degraded" },
      }),
    });
    expect(html).toMatch(/class="shield yellow"/);
  });

  it("applies the correct shield color class for red status", () => {
    const html = renderDashboardHTML({
      snapshot: makeSnapshot({
        overall: { status: "compromised", light: "red", headline: "compromised" },
      }),
    });
    expect(html).toMatch(/class="shield red"/);
  });

  it("renders the hero copy from the exported HERO_COPY constant", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain(HERO_COPY);
  });

  it("renders the privacy boundary summary", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain("Privacy boundary");
    expect(html).toContain("Filtered spans");
    expect(html).toContain("email 1");
    expect(html).toContain("phone 1");
  });

  it("echoes the aggregator headline in the hero sub-text", () => {
    const snap = makeSnapshot({
      overall: { status: "healthy", light: "green", headline: "L1·L3·L4 full — L2 degraded" },
    });
    const html = renderDashboardHTML({ snapshot: snap });
    expect(html).toContain("L1·L3·L4 full");
  });

  it("shows the agent display name and DID fingerprint", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain("Test Agent");
    expect(html).toContain("z6MkAb…123456");
  });

  it("renders pending approvals with Allow + Deny buttons", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain("data-action=\"allow\"");
    expect(html).toContain("data-action=\"deny\"");
    expect(html).toContain(">Allow<");
    expect(html).toContain(">Deny<");
  });

  it("renders the activity table with the tool call entry", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain("state_write");
    expect(html).toContain("result-allowed");
  });

  it("shows the claim CTA when no Verascore score is attached", () => {
    const snap = makeSnapshot({
      layers: {
        ...makeSnapshot().layers,
        l4: {
          label: "L4 Reputation",
          state: "degraded",
          headline: "Claim your profile",
          score: null,
          profile_url: null,
          claim_cta: "Claim your profile at verascore.ai",
        },
      },
    });
    const html = renderDashboardHTML({ snapshot: snap });
    expect(html).toContain("Claim your profile at verascore.ai");
  });

  // v1.0 rc.1 finding I — the L4 claim CTA must be a real anchor, not
  // plain text. Operators on the dashboard need to click through to
  // claim a profile; pre-v1.0 they had to retype the URL into a browser.
  // The href targets www.verascore.ai directly to avoid the apex 307
  // redirect.
  it("renders the claim CTA as a clickable anchor to www.verascore.ai", () => {
    const snap = makeSnapshot({
      layers: {
        ...makeSnapshot().layers,
        l4: {
          label: "L4 Reputation",
          state: "degraded",
          headline: "Claim your profile",
          score: null,
          profile_url: null,
          claim_cta: "Claim your profile at verascore.ai",
        },
      },
    });
    const html = renderDashboardHTML({ snapshot: snap });
    expect(html).toContain('href="https://www.verascore.ai"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noopener noreferrer"');
    // The anchor wraps the entire CTA phrase, so the existing substring
    // still appears in the rendered HTML.
    expect(html).toContain("Claim your profile at verascore.ai");
  });

  it("falls back to the default CTA copy when claim_cta is null", () => {
    const snap = makeSnapshot({
      layers: {
        ...makeSnapshot().layers,
        l4: {
          label: "L4 Reputation",
          state: "degraded",
          headline: "Claim your profile",
          score: null,
          profile_url: null,
          claim_cta: null,
        },
      },
    });
    const html = renderDashboardHTML({ snapshot: snap });
    expect(html).toContain('href="https://www.verascore.ai"');
    expect(html).toContain("Claim your profile at verascore.ai");
  });

  it("escapes HTML in user-controlled fields to prevent XSS", () => {
    const snap = makeSnapshot({
      agent: {
        display_name: "<script>alert(1)</script>",
        did: "did:key:x",
        did_fingerprint: "x",
        identity_count: 1,
        primary_identity_id: "id-1",
      },
    });
    const html = renderDashboardHTML({ snapshot: snap });
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("embeds the initial snapshot so the page renders without waiting for fetch", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain("INITIAL_SNAPSHOT =");
    expect(html).toContain("\"server_version\":\"0.9.0-test\"");
  });

  it("injects the auth token into the client bootstrap when provided", () => {
    const html = renderDashboardHTML({
      snapshot: makeSnapshot(),
      authToken: "tok-abc",
    });
    expect(html).toContain('AUTH_TOKEN = "tok-abc"');
  });

  it("does not construct long-lived token URLs for API calls or SSE", () => {
    const html = renderDashboardHTML({
      snapshot: makeSnapshot(),
      authToken: "tok-abc",
    });
    expect(html).not.toContain("?token=");
    expect(html).toContain("/auth/session");
    expect(html).toContain("?session=");
  });

  // ─── v0.9.1: L4 evidence widget ──────────────────────────────────
  describe("L4 evidence widget", () => {
    function snapshotWithEvidence() {
      const base = makeSnapshot();
      return {
        ...base,
        layers: {
          ...base.layers,
          l4: {
            label: "L4 Reputation",
            state: "degraded" as const,
            headline: "Attached, but evidence is degraded",
            score: 82,
            profile_url: "https://verascore.ai/p/test",
            claim_cta: null,
            evidence: {
              attestation_count: 7,
              tier_distribution: {
                "verified-sovereign": 2,
                "verified-degraded": 0,
                "self-attested": 4,
                "unverified": 1,
              },
              most_recent_attestation_at: new Date(
                Date.now() - 3 * 24 * 60 * 60 * 1000
              ).toISOString(),
              dispute_count: 1,
              context_breakdown: { commerce: 5, negotiation: 2 },
              verascore_linked: true,
            },
            layer_score: 55,
            active_degradations: [
              {
                code: "LOW_TIER_DOMINANCE",
                severity: "info" as const,
                description: "71% of attestations are self-attested or unverified",
                mitigation: "Complete sovereignty handshakes with counterparties",
              },
              {
                code: "DISPUTE_ON_RECORD",
                severity: "warning" as const,
                description: "1 attestation marked as disputed",
                mitigation: "Review disputed interactions",
              },
            ],
          },
        },
      };
    }

    it("renders the L4 score and evidence counts when evidence is present", () => {
      const html = renderDashboardHTML({ snapshot: snapshotWithEvidence() });
      expect(html).toContain("L4 score");
      expect(html).toContain("55 / 100");
      expect(html).toContain("Attestations");
      expect(html).toContain(">7<");
      expect(html).toContain("Disputes");
      expect(html).toContain("Verascore link");
    });

    it("renders each active L4 degradation with code, severity, description, and mitigation", () => {
      const html = renderDashboardHTML({ snapshot: snapshotWithEvidence() });
      expect(html).toContain("LOW_TIER_DOMINANCE");
      expect(html).toContain("DISPUTE_ON_RECORD");
      expect(html).toMatch(/l4-deg-info/);
      expect(html).toMatch(/l4-deg-warning/);
      expect(html).toContain(
        "71% of attestations are self-attested or unverified"
      );
      expect(html).toContain("1 attestation marked as disputed");
      expect(html).toContain(
        "Complete sovereignty handshakes with counterparties"
      );
    });

    it("omits the evidence block entirely when l4.evidence is undefined", () => {
      const html = renderDashboardHTML({ snapshot: makeSnapshot() });
      // The evidence widget block and its rendered content do not appear.
      // (The CSS declarations for .l4-evidence always ship with the
      // stylesheet so consumers can theme them — we check the rendered
      // DOM instead.)
      expect(html).not.toContain(`<div class="l4-evidence">`);
      expect(html).not.toMatch(/<dt>L4 score<\/dt>/);
    });

    it("escapes HTML in evidence-derived fields", () => {
      const base = snapshotWithEvidence();
      base.layers.l4.active_degradations = [
        {
          code: "<script>x</script>",
          severity: "info",
          description: "<img src=x onerror=1>",
          mitigation: "</div>",
        },
      ];
      const html = renderDashboardHTML({ snapshot: base });
      expect(html).not.toContain("<script>x</script>");
      expect(html).not.toContain("<img src=x");
      expect(html).toContain("&lt;script&gt;");
    });
  });
});
