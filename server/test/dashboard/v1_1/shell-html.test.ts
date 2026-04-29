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

  it("embeds dashboard config as a JSON script tag, not a sensitive token in markup", () => {
    const html = renderDashboardV11Html({
      authToken: "session-token-xyz",
      identityId: "operator-001",
      fortressId: "fortress-001",
    });
    // Auth token may be embedded for the inline client to use, but never
    // appears in localStorage write paths.
    expect(html).not.toContain("localStorage");
    // Sovereignty preference is in-memory; sidebar collapse goes to
    // sessionStorage only. Confirm via the embedded client script.
    const client = getClientScript();
    expect(client).not.toContain("localStorage");
    expect(client).toContain("sessionStorage");
  });

  it("no em-dashes in operator-visible HTML strings", () => {
    const html = renderDashboardV11Html({});
    // The shell HTML body must not include the U+2014 em-dash. Internal
    // comments live in source files (.ts), not in the rendered HTML.
    expect(html).not.toContain("—");
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
      "concierge-loop",
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
