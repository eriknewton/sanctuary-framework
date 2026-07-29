/**
 * Sanctuary v1.1 Dashboard — Shell HTML tests.
 *
 * Covers required tests 7 + 9 + 10:
 *  - test 7: out-of-scope screens hidden — Federation, Composition routes
 *    do not appear in sidebar nav.
 *  - test 9: exit drill verifier-out-of-process — wizard step 4 displays
 *    CLI command; client script does NOT import any verifier function.
 *  - test 10: no raw chat command path — operator typed text does NOT
 *    produce a backend command POST at v1.1.
 *
 * Also assertions on the no-em-dash rule and the absence of UBAI / MLS
 * dead-claims in operator-visible copy.
 */

import { describe, expect, it } from "vitest";
import {
  renderDashboardV11Html,
  getClientScript,
} from "../../../src/dashboard/v1_1/index.js";

describe("v1.1 dashboard shell HTML", () => {
  it("renders the sidebar nav and excludes out-of-scope routes", () => {
    const html = renderDashboardV11Html({});
    expect(html).toContain('data-route="dashboard"');
    expect(html).toContain('data-route="agents"');
    expect(html).toContain('data-route="policy"');
    expect(html).toContain('data-route="privacy"');
    expect(html).toContain('data-route="coordination"');
    expect(html).toContain('data-route="health"');
    expect(html).toContain('data-route="exit-drill"');
    // Out-of-scope at v1.1 ship: federation, composition, full recovery.
    expect(html).not.toContain('data-route="federation"');
    expect(html).not.toContain('data-route="composition"');
    expect(html).not.toContain('data-route="recovery"');
  });

  it("embeds dashboard config as a JSON script tag without serializing the bearer", () => {
    const html = renderDashboardV11Html({
      authToken: "session-token-xyz",
      identityId: "operator-001",
      fortressId: "fortress-001",
    });
    expect(html).not.toContain("session-token-xyz");
    expect(html).not.toContain("localStorage");
    // Sovereignty preference is in-memory; sidebar collapse goes to
    // sessionStorage only. Confirm via the embedded client script.
    const client = getClientScript();
    expect(client).not.toContain("localStorage");
    expect(client).toContain("sessionStorage");
    expect(client).toContain('sessionStorage.getItem("authToken")');
  });

  it("uses short-lived sessions, not long-lived token URLs, for SSE", () => {
    const client = getClientScript();
    expect(client).not.toContain("?token=");
    expect(client).toContain("/auth/session");
    expect(client).toContain("?session=");
    expect(client).toContain("new EventSource(url)");
  });

  it("no em-dashes in operator-visible HTML strings", () => {
    const html = renderDashboardV11Html({});
    // The shell HTML body must not include the U+2014 em-dash. Internal
    // comments live in source files (.ts), not in the rendered HTML.
    expect(html).not.toContain("—");
  });

  // ── One-surface posture fold (default-flip 2026-06-30) ────────────────
  // The full posture detail is folded into the single default surface: a
  // Posture entry in the Verify group, a Posture screen renderer that reuses
  // the existing /api/posture/* data endpoints, and the seal click-to-expand
  // into that screen. Nothing is lost; nothing is duplicated.
  it("exposes a Posture entry in the sidebar (folded-in posture detail)", () => {
    const html = renderDashboardV11Html({});
    expect(html).toContain('data-route="posture"');
    // It sits in the Verify group alongside Activity / Attestation / Health.
    expect(html).toContain('data-route="activity"');
    expect(html).toContain('data-route="attestation"');
  });

  it("renders the folded Posture screen reusing the existing posture data endpoints", () => {
    const client = getClientScript();
    // The Posture screen renderer + its route are wired.
    expect(client).toContain("renderPostureScreen");
    expect(client).toContain('case "posture":');
    // It REUSES the existing posture data endpoints, never a duplicate API.
    expect(client).toContain("/api/posture/home");
    expect(client).toContain("/api/anomaly/findings");
    // The per-agent drill-down and the Evidence view stay reachable.
    expect(client).toContain("/posture/agent/");
    expect(client).toContain("/posture/evidence");
    // The six named metric cards from the posture board are folded in.
    expect(client).toContain("Protection requested");
    expect(client).toContain("Enforcement confirmed");
    expect(client).toContain("Castle Wall");
    expect(client).toContain("Approvals waiting");
    expect(client).toContain("Open anomalies");
    expect(client).toContain("Audit chain");
    // Today's story + the plain-summary toggle are folded in (apostrophe is
    // emitted as the &#39; entity so the raw client string is plain).
    expect(client).toContain("Today&#39;s story");
    expect(client).toContain("posture-story-plain");
    // Anomaly findings list is folded in.
    expect(client).toContain("Anomaly findings");
  });

  it("the seal click-to-expand routes into the full Posture detail", () => {
    const client = getClientScript();
    expect(client).toContain("posture-detail-open");
    expect(client).toContain("See full posture detail");
  });

  it("the folded posture detail honors the never-overclaim seal (green only on armed)", () => {
    const client = getClientScript();
    // Castle Wall reads green/Enforcing ONLY on an armed arm-state; the
    // per-agent pill reads green ONLY on confirmed live enforcement.
    expect(client).toContain('armState === "armed"');
    expect(client).toContain('a.enforcement_active === "active"');
  });

  it("the folded posture detail uses named layers only (no L1/L2/L3/L4 in copy)", () => {
    const client = getClientScript();
    // The Posture screen renderer block must not reintroduce L-numbering in
    // operator-visible copy. Scan the renderPostureScreen region for the
    // retired tokens as standalone layer labels.
    const start = client.indexOf("function renderPostureScreen");
    const region = start >= 0 ? client.slice(start, start + 4000) : client;
    expect(region).not.toMatch(/\bL1 Cognitive\b/);
    expect(region).not.toMatch(/\bL2 Operational\b/);
    expect(region).not.toMatch(/\bL3\b/);
    expect(region).not.toMatch(/\bL4 Reputation\b/);
  });

  it("no UBAI dead-claims in operator-visible copy", () => {
    const html = renderDashboardV11Html({});
    const client = getClientScript();
    const combined = html + "\n" + client;
    expect(combined.toLowerCase()).not.toContain("universal basic ai");
    expect(combined.toLowerCase()).not.toContain("universal basic intelligence");
    expect(combined.toLowerCase()).not.toContain("ai for everyone");
    expect(combined).not.toMatch(/\bUBAI\b/);
  });

  it("no MLS dead-claims in operator-visible copy", () => {
    const html = renderDashboardV11Html({});
    const client = getClientScript();
    const combined = html + "\n" + client;
    // v1.0 chat is AES-256-GCM per-epoch forward-secret; MLS is v1.4+.
    expect(combined).not.toContain("MLS");
    expect(combined).not.toContain("RFC 9420");
    expect(combined.toLowerCase()).not.toContain("forward secrecy via mls");
  });

  it("renders the binary version pill (Finding CCC, v1.2.0-rc.3)", () => {
    const html = renderDashboardV11Html({ sanctuaryVersion: "1.2.0-rc.3" });
    // S2 (2026-07-18): the version / deployment / mode / attestation chips
    // moved off the top bar into the sidebar footer so the top bar carries
    // one overall state pill. The pill stays in the same flex container.
    // S3 (2026-07-18): the container id followed the chips -- "topbar-pills"
    // described a location they had already left, so it is now "sidebar-pills".
    expect(html).toContain('data-pill="version"');
    expect(html).toContain("v1.2.0-rc.3");
    const pillsMatch = html.match(/<div class="pills" id="sidebar-pills">[\s\S]*?<\/div>/);
    expect(pillsMatch).toBeTruthy();
    expect(pillsMatch![0]).toContain('data-pill="version"');
    expect(pillsMatch![0]).toContain('data-pill="deployment"');
  });

  it("renders a clickable link to /fleet as the Machines nav item (C1 Finding 4; S2 reorder)", () => {
    const html = renderDashboardV11Html({});
    // S2: the Fleet Switcher moved from a top-bar link to the "Machines" item
    // in the sidebar nav spine. The /fleet route stays reachable, unremoved.
    expect(html).toMatch(/<a[^>]+href="\/fleet"[^>]*>/);
    const navMatch = html.match(/<nav id="sidebar-nav">[\s\S]*?<\/nav>/);
    expect(navMatch).toBeTruthy();
    expect(navMatch![0]).toContain('href="/fleet"');
    expect(navMatch![0]).toContain("Machines");
  });

  it("falls back to the package binary version when sanctuaryVersion is unset", () => {
    const html = renderDashboardV11Html({});
    // Read the package.json version directly to compare against the default.
    // require + relative path mirrors the constant in config.ts.
    const pkgVersion = (require("../../../package.json") as { version: string }).version;
    expect(html).toContain('data-pill="version"');
    expect(html).toContain("v" + pkgVersion);
  });

  it("emits sanctuaryVersion in the dashboard-config JSON block so renderTopbar can refresh the pill", () => {
    const html = renderDashboardV11Html({ sanctuaryVersion: "1.2.0-rc.3" });
    const configBlockMatch = html.match(
      /<script id="dashboard-config" type="application\/json">([\s\S]*?)<\/script>/,
    );
    expect(configBlockMatch).toBeTruthy();
    const cfg = JSON.parse(configBlockMatch![1]!) as { sanctuaryVersion?: string };
    expect(cfg.sanctuaryVersion).toBe("1.2.0-rc.3");
  });

  it("preserves signature_scheme as internal-only (not surfaced in HTML)", () => {
    const html = renderDashboardV11Html({});
    // Per binding addendum acceptance criterion 6: the scheme value is
    // not displayed in operator-facing copy. A "Signature: valid"
    // indicator is acceptable; the literal string "ed25519-v1" is not
    // surfaced to the operator.
    expect(html).not.toContain("ed25519-v1");
  });

  it("embeds the v1.1 contract version constant in the client script", () => {
    // The client mirrors the template registry from server-side
    // templates.ts. The presence of the registry's first key proves the
    // mirror landed.
    const client = getClientScript();
    expect(client).toContain("approval_pending.tier1.lockdown");
  });

  it("renders the v1.2 Policy Center template binding surface", () => {
    const client = getClientScript();
    for (const id of [
      "request-approve-act",
      "read-then-report",
      "scheduled-digest",
      "plan-draft-only",
      "fortress-relay",
    ]) {
      expect(client).toContain(id);
    }
    expect(client).toContain("Per-agent rules");
    expect(client).toContain("template-picker-open");
    expect(client).toContain('body: { template_id: templateId }');
  });
});

describe("v1.1 dashboard exit drill verifier-out-of-process", () => {
  it("renders verify and import as CLI commands, not in-process calls", () => {
    const client = getClientScript();
    expect(client).toContain("verify-exit-bundle");
    expect(client).toContain("import-exit-bundle");
  });

  it("does NOT import the verifier function into the client module graph", () => {
    const client = getClientScript();
    // The dashboard process must never call verifyExitBundle in-process.
    // The CLI instructs the operator to run on a fresh shell. This is
    // the sovereignty-on-different-trust-boundary primitive.
    expect(client).not.toContain("verifyExitBundle(");
    expect(client).not.toContain("verifier.js");
    expect(client).not.toContain("import { verifyExitBundle");
  });
});

describe("v1.1 dashboard chat protocol", () => {
  it("ships no chat-composer submit handler at v1.1.7 (Finding EE)", () => {
    const client = getClientScript();
    // v1.1.7 (Finding EE) removed the half-built chat surface entirely.
    // No chat-composer form, no submit handler, no chat-input element.
    // The dashboard view renders a static "What you can do today" welcome
    // card — there is no path for operator-typed text to reach a backend
    // command at v1.1, by construction. Direct chat ships in v1.2.
    expect(client).not.toContain("chat-composer");
    expect(client).not.toContain("chat-input");
    expect(client).not.toContain('document.getElementById("chat-input")');
  });

  it("renders concierge advisory copy referencing v1.2 deferral", () => {
    const client = getClientScript();
    expect(client).toContain("v1.2");
    // Concierge surface explicitly named (in the welcome card's deferral
    // line: "Direct chat with the concierge ships in v1.2.").
    expect(client.toLowerCase()).toContain("concierge");
  });
});
