/**
 * Dashboard HTML rendering tests — verifies the hero shield, the four
 * layer cards, hero copy, activity table, approval list, and audit
 * filters all render from a given snapshot.
 */

// fail-before-exempt: this change strengthens the existing shield-mark pin to run the client update path for each light; server/src/dashboard/html.ts is unchanged here, so the test passes on the base by design.
import { describe, it, expect } from "vitest";
import { runInNewContext } from "node:vm";
import { renderDashboardHTML, HERO_COPY } from "../../src/dashboard/html.js";
import type { ProtectionSnapshot } from "../../src/dashboard/aggregator.js";
import { PAPER_INK_ROOT_TOKENS_CSS, THEME_BOOTSTRAP_SCRIPT } from "../../src/dashboard/design-tokens.js";
import { CONSOLE_FONT_FACE_CSS } from "../../src/dashboard/design-fonts.js";
import { cssRules, inlineStyle, ownStyleProblems } from "./console-style-helpers.js";

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
    expect(html).toContain('id="shield-status-mark" d="M100 78 L122 120 L78 120 Z"');
    expect(html).not.toContain('id="shield-status-mark" d="M85 102 L96 113 L118 90"');
  });

  it("applies the correct shield color class for red status", () => {
    const html = renderDashboardHTML({
      snapshot: makeSnapshot({
        overall: { status: "compromised", light: "red", headline: "compromised" },
      }),
    });
    expect(html).toMatch(/class="shield red"/);
    expect(html).toContain('id="shield-status-mark" d="M84 84 L116 116 M116 84 L84 116"');
    expect(html).not.toContain('id="shield-status-mark" d="M85 102 L96 113 L118 90"');
  });

  it("the client shield update path uses the same mark paths as the server render", () => {
    const lights = ["green", "yellow", "red"] as const;
    const serverMarks = new Map(lights.map((light) => {
      const html = renderDashboardHTML({ snapshot: makeSnapshot({ overall: { status: "healthy", light, headline: "x" } }) });
      return [light, html.match(/id="shield-status-mark" d="([^"]+)"/)![1]!] as const;
    }));
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain("must match shieldStatusMark in server/src/dashboard/html.ts");
    const clientFns = html.match(/function shieldStatusMarkForLight\(light\) \{[\s\S]*?\n  \}\n\n  function renderShield\(light, headline\) \{[\s\S]*?\n  \}/)![0]!;
    for (const light of lights) {
      const updatedMark = runInNewContext(`
        const writes = [];
        const classList = { remove() {}, add() {} };
        const document = {
          getElementById: function (id) {
            if (id === "shield") return { classList };
            if (id === "shield-status-mark") return { setAttribute: function (key, value) { if (key === "d") writes.push(value); } };
            return { textContent: "" };
          }
        };
        function heroCopyForLight() { return "copy"; }
        ${clientFns}
        renderShield(${JSON.stringify(light)}, "headline");
        writes[0];
      `) as string;
      expect(updatedMark, light).toBe(serverMarks.get(light));
    }
  });

  it("renders the hero copy from the exported HERO_COPY constant", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain(`<h1 id="hero-copy">${HERO_COPY}</h1>`);
  });

  it("does not render the protected hero copy for non-green snapshots", () => {
    const html = renderDashboardHTML({
      snapshot: makeSnapshot({
        overall: {
          status: "degraded",
          light: "yellow",
          headline: "Castle Wall enforcement not confirmed",
        },
      }),
    });
    expect(html).not.toContain(`<h1 id="hero-copy">${HERO_COPY}</h1>`);
    expect(html).toContain('<h1 id="hero-copy">Protection not confirmed.</h1>');
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

  it("renders redacted pending approvals as hidden, not as an empty inbox", () => {
    const html = renderDashboardHTML({
      snapshot: makeSnapshot({
        pending_approvals: [],
        pending_approvals_redacted: true,
        pending_approvals_count: 1,
      }),
    });
    expect(html).toContain('data-pending-approvals-redacted="1"');
    expect(html).toContain("Approvals are hidden, not empty.");
    expect(html).toContain("Pending count: 1");
    const initialMarkup = html.slice(0, html.indexOf("<script>"));
    expect(initialMarkup).not.toContain("No pending approvals");
  });

  it("does not inject the auth token into the client bootstrap when provided", () => {
    const html = renderDashboardHTML({
      snapshot: makeSnapshot(),
      authToken: "tok-abc",
    });
    expect(html).not.toContain("tok-abc");
    expect(html).toContain('sessionStorage.getItem("authToken")');
    expect(html).toContain("promptForOperatorToken");
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

// Slice 2b: the pre-v1.1 dashboard reads the console design system (the
// server tokens and the bundled faces) instead of a system font stack and a
// palette of its own, and its states read in monochrome.
describe("renderDashboardHTML reads the console design system", () => {
  const shared = { fonts: CONSOLE_FONT_FACE_CSS, tokens: PAPER_INK_ROOT_TOKENS_CSS };

  it("carries the token block, the bundled faces and the theme bootstrap, and no palette or font of its own", () => {
    for (const light of ["green", "yellow", "red"] as const) {
      const html = renderDashboardHTML({ snapshot: makeSnapshot({ overall: { status: "healthy", light, headline: "x" } }) });
      expect(ownStyleProblems(html, shared), light).toEqual([]);
      expect(html, light).toContain(`<script>${THEME_BOOTSTRAP_SCRIPT}</script>`);
      expect(html, light).toMatch(/font-family: var\(--sans\)/);
      expect(html, light).toMatch(/var\(--mono\)/);
    }
  });

  it("its title has no em-dash", () => {
    const html = renderDashboardHTML({ snapshot: makeSnapshot() });
    expect(html).toContain("<title>Sanctuary: Sovereignty Dashboard</title>");
  });

  it("each layer and upstream-server state wears its own dot shape, so a state never rides on hue alone", () => {
    const rules = cssRules(inlineStyle(renderDashboardHTML({ snapshot: makeSnapshot() })));
    const decls = (sel: string) => new Map(rules.filter((r) => r.selector === sel).flatMap((r) => r.decls));
    const shape = (base: string, state: string | null) => {
      const d = decls(base);
      if (state) for (const [k, v] of decls(state)) d.set(k, v);
      return ["clip-path", "border-radius", "height", "border", "background"].map((k) => k + ":" + (d.get(k) ?? "")).join(" ");
    };
    const layer = [null, ".layer-full .layer-dot", ".layer-degraded .layer-dot", ".layer-compromised .layer-dot"].map((s) => shape(".layer-dot", s));
    expect(new Set(layer.map((x) => x.replace(/background:var\(--[a-z-]+\)/, ""))).size).toBe(layer.length);
    const server = [null, ".server-row.state-connected .server-dot", ".server-row.state-connecting .server-dot",
      ".server-row.state-disconnected .server-dot, .server-row.state-error .server-dot"].map((s) => shape(".server-dot", s));
    expect(new Set(server.map((x) => x.replace(/background:var\(--[a-z-]+\)/, ""))).size).toBe(server.length);
    // The base state (no evidence of a state) is the hollow dotted slate ring.
    expect(decls(".layer-dot").get("border")).toMatch(/dotted var\(--slate\)/);
    expect(decls(".server-dot").get("border")).toMatch(/dotted var\(--slate\)/);
  });
});
