/**
 * Console shell non-text contrast and mark shapes.
 *
 * Capability: every boundary a person must find on a shell control (buttons,
 * the range select, inputs, the scope trigger, the option tiles) clears the
 * 3:1 non-text floor against every console fill in both themes; no mark a
 * person must perceive is painted in --ink-4 (under 3:1 on every fill), which
 * stays for disabled-control text only; and every state mark family gives each
 * state its own shape, so a state reads in monochrome and never by hue alone.
 * Every ratio is computed from the frozen token values.
 *
 * Also pinned here: the Agents list keeps a single track at every width (a
 * second track cut the list's subline), and the narrow top-bar rule that lets
 * the bar fit from 860px up.
 */

import { describe, it, expect } from "vitest";
import { renderDashboardV11Html } from "../../../src/dashboard/v1_1/html.js";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import {
  CONSOLE_FILLS,
  NON_TEXT_FLOOR,
  contrast,
  cssRules,
  inlineStyle,
  minRatio,
  themeTokens,
  tokenOf,
  type CssRule,
} from "../console-style-helpers.js";

const tokens = themeTokens();
const css = inlineStyle(renderDashboardV11Html({ embedClient: false }));
const rules = cssRules(css);
const topLevel = rules.filter((r) => r.media === null);
const TOKEN_BLOCK_SELECTORS = new Set([":root", '[data-theme="dark"]']);

/** The class names a selector's subject (its last compound) carries, with
 *  pseudo-classes and pseudo-elements removed. */
function subjectClasses(selector: string): string[][] {
  return selector.split(",").map((part) => {
    const compounds = part.trim().split(/\s+/);
    const subject = compounds[compounds.length - 1]!.replace(/::?[a-z-]+(\([^)]*\))?/gi, "");
    return [...subject.matchAll(/\.([a-z0-9_-]+)/gi)].map((m) => m[1]!)
      .concat(/^input|^select|^textarea/i.test(subject) ? [subject.replace(/\[.*$/, "")] : []);
  });
}

/** Classes (and bare elements) that name a control a person operates. */
const CONTROL_SUBJECTS = new Set([
  "btn", "btn-quiet", "iconbtn", "scope", "search", "range", "input",
  "concierge-suggest", "template-option", "intel-option", "input-wrap",
  "select", "textarea",
]);

function edgeDecls(rule: CssRule): Array<[string, string]> {
  return rule.decls.filter(([p]) => /^border(-(top|right|bottom|left))?(-color)?$/.test(p));
}

describe("shell control boundaries clear 3:1 in both themes", () => {
  const controlRules = rules.filter((r) =>
    !TOKEN_BLOCK_SELECTORS.has(r.selector) &&
    subjectClasses(r.selector).some((names) => names.some((n) => CONTROL_SUBJECTS.has(n))),
  );

  it("finds the controls the brief names and every console fill, so the sweep below is not vacuous", () => {
    for (const f of CONSOLE_FILLS) {
      expect(tokens.light[f], f).toMatch(/^#[0-9a-f]{6}$/);
      expect(tokens.dark[f], f).toMatch(/^#[0-9a-f]{6}$/);
    }
    const selectors = new Set(controlRules.map((r) => r.selector));
    for (const s of [".btn", ".scope", ".search", ".range", ".iconbtn", ".input", ".btn-quiet",
      ".template-option", ".intel-option", ".concierge-suggest", ".concierge-composer .input-wrap",
      ".composer input", ".auto-trigger-form input"]) {
      expect(selectors.has(s), s).toBe(true);
    }
  });

  it("every control edge painted with a token clears 3:1 against every console fill", () => {
    let checked = 0;
    for (const rule of controlRules) {
      for (const [prop, value] of edgeDecls(rule)) {
        const token = tokenOf(value);
        if (!token) continue;
        for (const theme of ["light", "dark"] as const) {
          const worst = minRatio(tokens[theme], token);
          expect(worst.ratio, `${rule.selector} ${prop} var(--${token}) on --${worst.fill} (${theme})`)
            .toBeGreaterThanOrEqual(NON_TEXT_FLOOR);
        }
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(20);
  });

  it("a control's resting edge is a visible stroke, not border 0 or transparent", () => {
    for (const s of [".btn", ".scope", ".search", ".range", ".iconbtn", ".input", ".btn-quiet",
      ".template-option", ".intel-option", ".concierge-suggest", ".concierge-composer .input-wrap"]) {
      const rule = topLevel.find((r) => r.selector === s)!;
      const edge = edgeDecls(rule).map(([, v]) => v).join(" ");
      expect(edge, s).toMatch(/1px solid var\(--/);
    }
  });
});

describe("--ink-4 paints disabled text only", () => {
  it("the shell CSS and the client's inline styles use --ink-4 only as the text color of a disabled control", () => {
    // --ink-4 is under 3:1 on the console fills in both themes, which is why
    // it may paint no mark a person must perceive.
    for (const theme of ["light", "dark"] as const) {
      expect(minRatio(tokens[theme], "ink-4").ratio, theme).toBeLessThan(NON_TEXT_FLOOR);
    }
    const uses = rules.filter((r) => !TOKEN_BLOCK_SELECTORS.has(r.selector))
      .flatMap((r) => r.decls.filter(([, v]) => v.includes("--ink-4")).map(([p]) => ({ sel: r.selector, prop: p })));
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) {
      expect(u.prop, u.sel).toBe("color");
      expect(u.sel, u.sel).toContain(":disabled");
    }
    expect(getClientScript()).not.toContain("ink-4");
  });
});

/** A state mark family: the selector for each state, in cascade order after
 *  the base. */
interface MarkFamily {
  name: string;
  base: string;
  states: Record<string, string | null>;
}

const MARK_FAMILIES: MarkFamily[] = [
  { name: "agent state dot", base: ".state-dot",
    states: { unknown: null, live: ".state-dot.live", idle: ".state-dot.idle", off: ".state-dot.off", locked: ".state-dot.locked" } },
  { name: "agent status glyph", base: ".glyph",
    states: { unknown: null, online: ".glyph.online", idle: ".glyph.idle", away: ".glyph.away", offline: ".glyph.offline" } },
  { name: "timeline mark", base: ".timeline-item::before",
    states: { neutral: null, ok: ".timeline-item.ok::before", warn: ".timeline-item.warn::before", fail: ".timeline-item.fail::before" } },
  { name: "posture layer dot", base: ".posture-seal-pop .pp-dot, .enforcement-layers .pp-dot",
    states: {
      pass: null,
      warn: ".posture-seal-pop .pp-dot.warn, .enforcement-layers .pp-dot.warn",
      off: ".posture-seal-pop .pp-dot.off, .enforcement-layers .pp-dot.off",
      unknown: ".posture-seal-pop .pp-dot.unknown, .enforcement-layers .pp-dot.unknown",
    } },
  { name: "auto-trigger trend bar", base: ".trend-bar",
    states: { other: null, good: ".trend-bar.good", warn: ".trend-bar.warn" } },
  { name: "machine health chip", base: ".state-chip i",
    states: { unknown: ".state-chip.unknown i", checking: ".state-chip.checking i", online: ".state-chip.good i", notHealthy: ".state-chip.bad i" } },
];

function declsOf(selector: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const r of topLevel.filter((x) => x.selector === selector)) for (const [p, v] of r.decls) out.set(p, v);
  return out;
}

function effective(family: MarkFamily, state: string): Map<string, string> {
  const merged = declsOf(family.base);
  expect(merged.size, `${family.name} base rule`).toBeGreaterThan(0);
  const sel = family.states[state];
  if (sel) {
    const own = declsOf(sel);
    expect(own.size, `${family.name} ${state} rule`).toBeGreaterThan(0);
    for (const [p, v] of own) {
      // A border shorthand resets the whole edge; carry that through.
      if (p === "border") merged.delete("border-style");
      merged.set(p, v);
    }
  }
  return merged;
}

function shapeOf(d: Map<string, string>): string {
  const border = d.get("border") ?? "0";
  const style = d.get("border-style") ?? (border.match(/\b(solid|dotted|dashed)\b/)?.[1] ?? "none");
  const hollow = (d.get("background") ?? "") === "transparent";
  const radius = d.get("border-radius") ?? "0";
  const radiusClass = radius === "50%" || radius === "999px" ? "round" : "square";
  return [
    `clip:${d.get("clip-path") ?? "none"}`,
    `radius:${radiusClass}`,
    `w:${d.get("width") ?? "?"}`,
    `h:${d.get("height") ?? "?"}`,
    `edge:${border === "0" ? "none" : style}`,
    hollow ? "hollow" : "filled",
  ].join(" ");
}

function paintOf(d: Map<string, string>): string | null {
  const bg = d.get("background") ?? "";
  if (bg && bg !== "transparent") return tokenOf(bg);
  return tokenOf(d.get("border") ?? "");
}

describe("each state mark family reads in monochrome", () => {
  for (const family of MARK_FAMILIES) {
    it(`${family.name}: every state has its own shape`, () => {
      const shapes = new Map<string, string>();
      for (const state of Object.keys(family.states)) {
        const shape = shapeOf(effective(family, state));
        const clash = [...shapes].find(([, s]) => s === shape);
        expect(clash, `${family.name}: ${state} has the same shape as ${clash?.[0]} (${shape})`).toBeUndefined();
        shapes.set(state, shape);
      }
    });

    it(`${family.name}: every state's paint clears 3:1 on every console fill`, () => {
      for (const state of Object.keys(family.states)) {
        const token = paintOf(effective(family, state));
        expect(token, `${family.name} ${state} paints with a token`).toBeTruthy();
        for (const theme of ["light", "dark"] as const) {
          const worst = minRatio(tokens[theme], token!);
          expect(worst.ratio, `${family.name} ${state} var(--${token}) on --${worst.fill} (${theme})`)
            .toBeGreaterThanOrEqual(NON_TEXT_FLOOR);
        }
      }
    });
  }

  it("machine chip marks clear 3:1 against their own chip tints in both themes", () => {
    const pairs = [
      ["online", ".state-chip.good i", "sage-bg"],
      ["not healthy", ".state-chip.bad i", "rust-bg"],
      ["unknown", ".state-chip.unknown i", "slate-bg"],
      ["checking", ".state-chip.checking i", "slate-bg"],
    ] as const;
    for (const [name, selector, fill] of pairs) {
      const token = paintOf(effective({ name: "machine chip", base: ".state-chip i", states: { mark: selector } }, "mark"));
      expect(token, name).toBeTruthy();
      for (const theme of ["light", "dark"] as const) {
        const ratio = contrast(tokens[theme][token!]!, tokens[theme][fill]!);
        expect(ratio, `${name} mark var(--${token}) on --${fill} (${theme})`).toBeGreaterThanOrEqual(NON_TEXT_FLOOR);
      }
    }
  });

  it("the Unknown state of every family that has one is the hollow dotted slate ring", () => {
    for (const family of MARK_FAMILIES) {
      if (!("unknown" in family.states)) continue;
      const d = effective(family, "unknown");
      expect(d.get("background"), family.name).toBe("transparent");
      expect(d.get("border"), family.name).toMatch(/dotted var\(--slate\)/);
    }
  });

  it("locked marks are hollow solid squares and the Not healthy chip uses the full rust stroke", () => {
    expect(declsOf(".glyph.offline").get("background")).toBe("transparent");
    expect(declsOf(".glyph.offline").get("border")).toMatch(/solid var\(--locked\)/);
    expect(declsOf(".state-dot.locked").get("background")).toBe("transparent");
    expect(declsOf(".state-dot.locked").get("border")).toMatch(/solid var\(--locked\)/);
    expect(declsOf(".state-chip.bad").get("border-color")).toBe("var(--rust)");
    expect(getClientScript()).toContain('state_CHECKING: { word: "Checking", cls: "checking" }');
  });

});

describe("layout rules the slice holds", () => {
  it("the Agents list keeps a single track at every width", () => {
    const d = declsOf(".agents-layout");
    expect(d.get("grid-template-columns")).toBe("minmax(0, 1fr)");
  });

  it("below 1400px the Approvals drawer stacks under the queue so the table keeps every column", () => {
    // 1400 = the table's 654px of columns plus the 742px the rail, padding, 420px drawer and gap take at 1280, rounded up.
    const stacked = rules.filter((r) => r.media === "@media (max-width: 1400px)");
    const by = (s: string) => new Map(stacked.filter((r) => r.selector === s).flatMap((r) => r.decls));
    expect(by(".approval-layout").get("grid-template-columns")).toBe("minmax(0, 1fr)");
    expect(by(".approval-drawer").get("position")).toBe("static");
  });

  it("below 1000px the top bar drops the brand and collapses search to its icon until focused", () => {
    const narrow = rules.filter((r) => r.media === "@media (max-width: 1000px)");
    const by = (s: string) => new Map(narrow.filter((r) => r.selector === s).flatMap((r) => r.decls));
    expect(by(".brand").get("display")).toBe("none");
    expect(by(".search input").get("width")).toBe("0");
    expect(by(".search-wrap:focus-within .search").get("position")).toBe("absolute");
    expect(by(".search-wrap:focus-within .search input").get("width")).toBe("auto");
    expect(css).toContain("@media (max-width: 1240px)");
    expect(css).toContain(".topbar .btn.btn-talk .btn-label { display: none; }");
  });

  it("the Evidence raw record wraps an unbroken served token inside the pane", () => {
    const d = declsOf(".evidence-detail .json");
    expect(d.get("white-space")).toBe("pre-wrap");
    expect(d.get("overflow-wrap")).toBe("anywhere");
  });

  it("the card head keeps action buttons on one line at the measured narrow widths", () => {
    const buttonRule = declsOf(".card-head-row .btn");
    expect(buttonRule.get("white-space")).toBe("nowrap");
  });
});

it('held-subject text inside a primary button computes at least 4.5:1 in both themes', () => {
  const primary = declsOf('.btn.btn-primary');
  const subject = declsOf('.held-subject');
  const override = declsOf('.btn .held-subject');
  for (const theme of ['light', 'dark'] as const) {
    const foreground = tokenOf(primary.get('color')! )!;
    const backgroundValue = override.get('background') ?? subject.get('background')!;
    const background = tokenOf(backgroundValue === 'transparent' ? primary.get('background')! : backgroundValue)!;
    expect(contrast(tokens[theme][foreground]!, tokens[theme][background]!), theme).toBeGreaterThanOrEqual(4.5);
  }
});
