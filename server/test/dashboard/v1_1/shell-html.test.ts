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
import { createContext, runInContext } from "node:vm";
import {
  renderDashboardV11Html,
  getClientScript,
} from "../../../src/dashboard/v1_1/index.js";
import { THEME_BOOTSTRAP_SCRIPT } from "../../../src/dashboard/design-tokens.js";

describe("v1.1 dashboard shell HTML", () => {
  it("renders the sidebar nav and excludes out-of-scope routes", () => {
    const html = renderDashboardV11Html({});
    // Slice 2 rail: the eight destinations plus Configure (order is pinned in
    // shell-route-walk.test.ts).
    for (const id of ["posture", "approvals", "agents", "enforcement", "findings", "activity", "policy", "integrations", "settings"]) {
      expect(html).toContain(`data-route="${id}"`);
    }
    // Retargeted (slice 2 shell): Talk, Privacy, Coordination, Health and
    // Exit drill left the rail; each folded id resolves through the client's
    // rail-parent table and still renders on its own hash.
    const client = getClientScript();
    expect(client).toContain('"dashboard": null');
    expect(client).toContain('"privacy": "settings"');
    expect(client).toContain('"coordination": "integrations"');
    expect(client).toContain('"health": "settings"');
    expect(client).toContain('"exit-drill": "activity"');
    // Out-of-scope at v1.1 ship: federation, composition, full recovery.
    expect(html).not.toContain('data-route="federation"');
    expect(html).not.toContain('data-route="composition"');
    expect(html).not.toContain('data-route="recovery"');
    expect(client).not.toContain('case "federation"');
    expect(client).not.toContain('case "composition"');
    expect(client).not.toContain('case "recovery"');
  });

  it("locked status paints the violet locked hue, never the fault red", () => {
    const html = renderDashboardV11Html({ embedClient: false });
    // Locked down is an operator decision, not a failure: the pill, the
    // top-bar seal and the ambient seal all read --locked with its tint and
    // line, and none of them reads the --rust fault hue.
    const rule = (selector: string) => {
      const esc = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const m = html.match(new RegExp(`(?:^|\\n)${esc} \\{([^}]*)\\}`));
      expect(m, selector).toBeTruthy();
      return m![1]!;
    };
    const pill = rule(".pill.tone-locked");
    expect(pill).toContain("var(--locked-bg)");
    expect(pill).toContain("color: var(--locked)");
    expect(pill).toContain("var(--locked-line)");
    expect(pill).not.toContain("--rust");
    const seal = rule(".posture-seal.tone-locked");
    expect(seal).toContain("var(--locked-bg)");
    expect(seal).toContain("color: var(--locked)");
    expect(seal).toContain("var(--locked-line)");
    expect(seal).not.toContain("--rust");
    const ambient = rule(".ambient-seal.tone-locked .as-glyph");
    expect(ambient).toContain("color: var(--locked)");
    expect(ambient).not.toContain("--rust");
    // No combined selector smuggles the locked tone back onto the fault red
    // (comments stripped first: the token block's prose names these selectors).
    const css = html.replace(/\/\*[\s\S]*?\*\//g, "");
    expect(css).not.toMatch(/tone-locked[^{]*\{[^}]*--rust/);
  });

  it("a bare link in the main column reads the accent, never the user-agent blue", () => {
    // Dark is the default theme, and the user-agent link blue on the dark
    // paper is about 2:1, under the 4.5:1 text floor. One rule colors every
    // non-button anchor in the main column, visited and hover included.
    const html = renderDashboardV11Html({ embedClient: false });
    const css = html.replace(/\/\*[\s\S]*?\*\//g, "");
    const m = css.match(/(?:^|\n)\.main a:not\(\.btn\), \.main a:not\(\.btn\):visited, \.main a:not\(\.btn\):hover \{([^}]*)\}/);
    expect(m, ".main a:not(.btn) rule").toBeTruthy();
    expect(m![1]).toContain("color: var(--accent)");
  });

  it("the stylesheet's braces balance: no unmatched closer, depth zero at the end", () => {
    // CSS error recovery folds a stray closing brace into the next rule's
    // prelude and silently drops that rule, so a balanced stylesheet is a
    // rendering invariant, not a lint. Comments and quoted strings are skipped.
    const html = renderDashboardV11Html({ embedClient: false });
    const css = html.slice(html.indexOf("<style>") + "<style>".length, html.indexOf("</style>"));
    let depth = 0;
    let unmatched = 0;
    for (let i = 0; i < css.length; i++) {
      const c = css[i];
      if (c === "/" && css[i + 1] === "*") { const end = css.indexOf("*/", i + 2); i = end < 0 ? css.length : end + 1; continue; }
      if (c === '"' || c === "'") { let j = i + 1; while (j < css.length && css[j] !== c) j += css[j] === "\\" ? 2 : 1; i = j; continue; }
      if (c === "{") depth++;
      else if (c === "}") { if (depth === 0) unmatched++; else depth--; }
    }
    expect(unmatched, "unmatched closing braces").toBe(0);
    expect(depth, "unclosed blocks at the end").toBe(0);
  });

  it("the engaged Lock down state keeps the bad text and bad-line border with no fill", () => {
    // Lock down is the one danger-styled control, and it never paints a red
    // fill, engaged included: an engaged lockdown is a decision on record,
    // not an alarm.
    const css = renderDashboardV11Html({ embedClient: false }).replace(/\/\*[\s\S]*?\*\//g, "");
    const m = css.match(/(?:^|\n)\.btn\.btn-lockdown\.tier1-engaged(?:, [^{]+)? \{([^}]*)\}/);
    expect(m, ".btn.btn-lockdown.tier1-engaged rule").toBeTruthy();
    expect(m![1]).toContain("background: transparent");
    expect(m![1]).toContain("color: var(--rust)");
    expect(m![1]).toContain("border-color: var(--rust-line)");
    expect(m![1]).not.toContain("--rust-bg");
  });

  it("no Lock down state paints the rust fill: idle, hover, focus and engaged keep text and line only", () => {
    const css = renderDashboardV11Html({ embedClient: false }).replace(/\/\*[\s\S]*?\*\//g, "");
    const rules = [...css.matchAll(/(?:^|\n)([^{}\n]*btn-lockdown[^{}\n]*) \{([^}]*)\}/g)];
    expect(rules.length).toBeGreaterThan(0);
    expect(rules.map((m) => m[1])).toEqual(expect.arrayContaining([expect.stringContaining(":hover")]));
    for (const m of rules) {
      expect(m[2], m[1]).not.toContain("--rust-bg");
      const bg = m[2]!.match(/background:\s*([^;]+)/);
      if (bg) expect(bg[1]!.trim(), m[1]).toBe("transparent");
    }
  });

  it("a folded section carries its own styled head, and the hosted page's eyebrow and h1 do not repeat", () => {
    const css = renderDashboardV11Html({ embedClient: false }).replace(/\/\*[\s\S]*?\*\//g, "");
    const rule = (selector: string) => {
      const esc = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const m = css.match(new RegExp(`(?:^|\\n)${esc} \\{([^}]*)\\}`));
      expect(m, selector).toBeTruthy();
      return m![1]!;
    };
    // The fold's eyebrow reads as an eyebrow (mono, uppercase), and its title
    // is a section heading, not body text.
    expect(rule(".folded-section > .folded-head .eyebrow")).toContain("text-transform: uppercase");
    expect(rule(".folded-section > .folded-head h2")).toContain("font-family: var(--display)");
    // The hosted page's own eyebrow and h1 are hidden inside a fold (the
    // fold's head carries them), wherever the hosted renderer puts them.
    const hide = rule(".folded-section > .page-head .eyebrow, .folded-section > .page-head h1, .folded-section > .policy-center > .eyebrow, .folded-section > .policy-center > h1, .folded-section > h1");
    expect(hide).toContain("display: none");
    // Both folds name their hosted page in the fold head.
    const client = getClientScript();
    expect(client).toContain('renderFoldedSection("Honeypots", "Honeypot traps.", "honeypot"');
    expect(client).toContain('renderFoldedSection("Auto-trigger ladder", "Calibration", "auto-trigger"');
  });

  it("the theme bootstrap yields dark with empty storage, and an explicit light choice wins", () => {
    const run = (storage: { getItem: (k: string) => string | null }) => {
      const attrs: Record<string, string> = {};
      const context = createContext({
        sessionStorage: storage,
        document: { documentElement: { setAttribute: (k: string, v: string) => { attrs[k] = v; } } },
      });
      runInContext(THEME_BOOTSTRAP_SCRIPT, context);
      return attrs["data-theme"];
    };
    expect(run({ getItem: () => null })).toBe("dark");
    expect(run({ getItem: () => "dark" })).toBe("dark");
    expect(run({ getItem: () => "light" })).toBeUndefined();
    expect(run({ getItem: () => { throw new Error("storage blocked"); } })).toBe("dark");
    // The shell runs the same bootstrap in its head, before first paint.
    const html = renderDashboardV11Html({ embedClient: false });
    expect(html.indexOf(THEME_BOOTSTRAP_SCRIPT)).toBeGreaterThan(0);
    expect(html.indexOf(THEME_BOOTSTRAP_SCRIPT)).toBeLessThan(html.indexOf("<style>"));
  });

  it("the client's theme fallback is dark with no explicit choice and light only when chosen", () => {
    const boot = (choice: string | null) => {
      const calls: string[] = [];
      const context = createContext({
        document: {
          getElementById: () => null, addEventListener() {}, querySelectorAll: () => [],
          documentElement: {
            setAttribute: (k: string, v: string) => calls.push(`set ${k}=${v}`),
            removeAttribute: (k: string) => calls.push(`remove ${k}`),
          },
        },
        // An OS that prefers light must not pull the no-choice state to light.
        window: { addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }) },
        location: { hash: "", search: "", origin: "http://fixture" },
        sessionStorage: { getItem: (k: string) => (k === "sanctuary-v11-theme" ? choice : null) },
        URLSearchParams, URL, AbortController, Date, Element: class {},
        setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
        EventSource: class { addEventListener() {} close() {} },
        fetch: () => new Promise<never>(() => {}),
      });
      runInContext(getClientScript(), context);
      return calls;
    };
    expect(boot(null)).toContain("set data-theme=dark");
    expect(boot("dark")).toContain("set data-theme=dark");
    expect(boot("light")).toContain("remove data-theme");
    expect(boot("light")).not.toContain("set data-theme=dark");
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
    // It leads the rail, with Evidence (activity) beside it.
    expect(html).toContain('data-route="activity"');
    // Retargeted (slice 2 shell): Attestation is a Settings tab, not a rail item.
    expect(getClientScript()).toContain('{ id: "attestation", label: "Attestation" }');
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
    // Retargeted (slice 2 shell): the nav now carries aria-label="Primary".
    const navMatch = html.match(/<nav id="sidebar-nav"[^>]*>[\s\S]*?<\/nav>/);
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
