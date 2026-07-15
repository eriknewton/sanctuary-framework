/**
 * F2 BLOCKER-1 (adversarial re-gate round 3, 2026-07-14) ANTI-REGRESSION,
 * hardened to PER-OCCURRENCE in round 4 (HIGH-2, 2026-07-15).
 *
 * The round-1/2 fix routed the sealed-region verdict into cleanliness claims
 * per-surface, which is whack-a-mole: a future surface (or a resurrected old
 * one) can compute "the audit chain is verified/clean" straight off
 * `integrity_findings.length` or a raw `chain_verified` boolean and skip the
 * sealed-region crypto verdict the operator hot-path deliberately omits. Round 3
 * collapsed the decision into ONE chokepoint, `AuditLog.getAuditChainVerdict()`
 * (folded via `auditChainVerdictClaimsClean` / `auditChainVerdictUntampered`).
 *
 * Round-4 HIGH-2: the original guard was FILE-level — a file passed if it
 * referenced any routing symbol ANYWHERE, so a second bypassing clean-claim in
 * an already-routed file slipped through (Codex's example: cooperative-surface.ts
 * routes `sanctuary_audit_search` but a different handler reads
 * `integrity_findings.length`). This version scans PER OCCURRENCE: every use of a
 * raw cleanliness signal must have a routing symbol within a bounded proximity
 * window OR carry an explicit `audit-chokepoint-exempt:` annotation (for a
 * fail-closed deny / renderer that is provably not a clean-claim). The
 * `flags a bypass in an already-routed file` test is the teeth: it runs the SAME
 * checker over synthetic source with one routed function plus one separate
 * bypassing clean-claim and asserts the bypass is caught.
 *
 * It is deliberately source-text-based (not a runtime test) so it catches the
 * bypass at authoring time, before any fortress is even constructed.
 *
 * HONEST SCOPE (round 5, both review families): this guard is a BEST-EFFORT
 * authoring-time backstop, not complete-by-construction. A line scan cannot
 * follow aliases across lines (it flags the alias MINT, not the later use), and
 * a bypass written within the proximity window of a genuinely different,
 * correctly-routed handler is laundered by proximity. The real enforcement is
 * the runtime chokepoint itself (`getAuditChainVerdict` + the collapse
 * helpers); this test raises the regression bar and catches every idiom named
 * by four rounds of adversarial review. Making it alias- and scope-exact needs
 * an AST/parser rewrite (see the repo's line-scanner-vs-parser escalation
 * discipline), tracked as follow-up, not claimed here.
 */

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");

const CHOKEPOINT = "getAuditChainVerdict";

// A surface is "routed through the shared verdict" if it references any of these
// shared symbols. Either it calls the convenience wrapper `getAuditChainVerdict`
// (routine full-chain findings + sealed verdict), or it folds its OWN routine
// count with the sealed verdict via the shared `foldAuditChainVerdict` and then
// collapses through `auditChainVerdictClaimsClean` / `auditChainVerdictUntampered`.
const ROUTING_SYMBOLS = [
  "getAuditChainVerdict",
  "auditChainVerdictClaimsClean",
  "auditChainVerdictUntampered",
  "foldAuditChainVerdict",
];

// The explicit local escape hatch for a raw-signal use that is provably NOT a
// clean-claim (a fail-closed deny on findings, or a renderer). Placing it near
// the occurrence is a deliberate, reviewable act; a naked bypass has neither
// routing NOR this marker and fails.
const EXEMPTION_MARKER = "audit-chokepoint-exempt";

// The raw cleanliness signals a bypass would derive "clean" from. Each must be
// routed-or-exempt at EVERY occurrence (comments / description copy excluded).
// Round-5 tightening (two-family gate): beyond the direct `.length` read and the
// clean-claim label, also flag the LAUNDERING idioms both reviewers exploited:
//   - alias-minting: `const f = res.integrity_findings;` (later `f.length === 0`
//     is invisible to a line scan, so the MINT line is the enforcement point);
//   - destructuring: `const { integrity_findings } = res;` (same laundering);
//   - filter-emptiness: `integrity_findings.filter(...).length === 0` (no
//     `.length` directly after the property).
// Named regexes so offender output stays readable.
const RAW_SIGNALS: Array<{ name: string; re: RegExp }> = [
  { name: "integrity_findings.length", re: /integrity_findings\s*\.\s*length/ },
  { name: "verified_against_audit_chain", re: /verified_against_audit_chain/ },
  {
    name: "integrity_findings alias-mint",
    // An assignment whose right-hand side is a bare `.integrity_findings` read
    // (ends the expression): `x = res.integrity_findings;` / `= r.integrity_findings)`.
    re: /=\s*[A-Za-z_$][\w$.]*\.integrity_findings\s*[;,)\]]?\s*$/,
  },
  {
    name: "integrity_findings destructure",
    re: /\{[^{}]*\bintegrity_findings\b[^{}]*\}\s*=/,
  },
  {
    name: "integrity_findings.filter",
    re: /integrity_findings\s*\.\s*(filter|some|every|find)\b/,
  },
];

// How many lines around an occurrence count as "near" for a routing symbol or an
// exemption marker. Wide enough to cover a handler's claim+routing proximity,
// narrow enough that a DIFFERENT handler's routing in the same file does NOT
// launder a bypass (Codex's cooperative-surface handlers are ~70 lines apart).
const PROXIMITY_WINDOW = 25;

// The chokepoint is DEFINED here; it is allowed to reference the raw signals.
const CHOKEPOINT_HOME = "operational/audit-log.ts";

// Pure renderers / neutral surfaces that CONSUME the already-folded verdict
// (they read `digest.chain_verified` / `digest.chain_verdict`, a dot-property
// read, never re-derive it) or unconditionally report "unknown". Each carries a
// documented reason; adding to this list is a deliberate, reviewable act.
const CONSUMER_EXEMPT: Record<string, string> = {
  "principal-policy/posture-home-html.ts":
    "renderer: switches on the folded digest.chain_verdict string, derives nothing",
  "dashboard/v1_1/client.ts":
    "renderer: switches on the folded digest.chain_verdict string, derives nothing",
  "health/evidence.ts":
    "neutral: emits chain_verified:\"unknown\" unconditionally (no AuditLog, never a clean claim)",
};

/** Strip a trailing `// ...` line comment so a routing symbol MENTIONED in a
 * comment does not count as real routing. */
function codeOnly(line: string): string {
  const i = line.indexOf("//");
  return i === -1 ? line : line.slice(0, i);
}

function isCommentLine(line: string): boolean {
  const t = line.trimStart();
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("/*");
}

/**
 * A raw-signal occurrence is a potential CLEAN-CLAIM context unless it is a
 * comment, product-copy `description:` string, or a trailing-comment mention.
 * Those never derive a runtime cleanliness verdict.
 */
function isClaimContext(line: string, matchIdx: number): boolean {
  if (isCommentLine(line)) return false;
  if (line.includes("description:")) return false;
  const commentIdx = line.indexOf("//");
  if (commentIdx !== -1 && commentIdx < matchIdx) return false; // in a trailing comment
  return true;
}

/** True when a routing symbol (in real code, not a comment) OR an exemption
 * marker appears within {@link PROXIMITY_WINDOW} lines of `idx`. */
function routedOrExemptNear(lines: string[], idx: number): boolean {
  const lo = Math.max(0, idx - PROXIMITY_WINDOW);
  const hi = Math.min(lines.length - 1, idx + PROXIMITY_WINDOW);
  for (let i = lo; i <= hi; i++) {
    const line = lines[i]!;
    if (line.includes(EXEMPTION_MARKER)) return true;
    const code = codeOnly(line);
    if (ROUTING_SYMBOLS.some((s) => code.includes(s))) return true;
  }
  return false;
}

/**
 * The PER-OCCURRENCE checker. Returns each raw-signal occurrence (in claim
 * context) that is neither near a routing symbol nor near an exemption marker.
 * Pure over `text` so the negative fixture can drive it on synthetic source.
 */
function unroutedOccurrences(text: string): Array<{ line: number; signal: string; snippet: string }> {
  const lines = text.split("\n");
  const out: Array<{ line: number; signal: string; snippet: string }> = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const signal of RAW_SIGNALS) {
      const m = signal.re.exec(line);
      if (!m) continue;
      if (!isClaimContext(line, m.index)) continue;
      if (routedOrExemptNear(lines, i)) continue;
      out.push({ line: i + 1, signal: signal.name, snippet: line.trim() });
      break; // one report per line is enough
    }
  }
  return out;
}

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

function rel(full: string): string {
  return relative(SERVER_SRC, full).split("\\").join("/");
}

describe("F2 BLOCKER-1: audit-chain cleanliness is derived ONLY through the shared verdict chokepoint", () => {
  const files = tsFiles(SERVER_SRC).map((full) => ({ rel: rel(full), text: readFileSync(full, "utf-8") }));

  it("the chokepoint and its two collapse helpers exist", () => {
    const home = files.find((f) => f.rel === CHOKEPOINT_HOME);
    expect(home, "audit-log.ts must define the chokepoint").toBeDefined();
    expect(home!.text).toContain(`async ${CHOKEPOINT}(`);
    expect(home!.text).toContain("export function auditChainVerdictClaimsClean");
    expect(home!.text).toContain("export function auditChainVerdictUntampered");
  });

  // PER-OCCURRENCE scan: EVERY use of a raw cleanliness signal (outside the
  // chokepoint home and the renderer/neutral exempt list) must have routing OR
  // an exemption marker within the proximity window. A second bypassing
  // clean-claim in an already-routed file no longer slips through.
  it("every raw-signal occurrence is routed through the chokepoint or explicitly exempt", () => {
    const offenders = files
      .filter((f) => f.rel !== CHOKEPOINT_HOME)
      .filter((f) => !(f.rel in CONSUMER_EXEMPT))
      .flatMap((f) =>
        unroutedOccurrences(f.text).map((o) => `${f.rel}:${o.line}  ${o.signal}  |  ${o.snippet}`),
      );
    expect(
      offenders,
      "these occurrences read a raw audit-chain cleanliness signal but have neither a routing " +
        "symbol nor an `audit-chokepoint-exempt:` annotation within " +
        `${PROXIMITY_WINDOW} lines. Route the cleanliness claim through the shared verdict (it folds ` +
        "the sealed-region crypto verdict the routine findings skip), or — if this is a fail-closed " +
        "deny / renderer that never stamps a clean label — annotate it with `audit-chokepoint-exempt: " +
        "<reason>`:\n" +
        offenders.join("\n"),
    ).toEqual([]);
  });

  // TEETH: the checker must FLAG a bypass added to an ALREADY-ROUTED file. This
  // synthetic source has a correctly-routed handler AND a second, separate
  // clean-claim handler that derives clean from `integrity_findings.length`
  // without routing — exactly the file-level guard's blind spot. The bypass sits
  // well outside the proximity window of the routed handler.
  it("flags a bypassing clean-claim in an already-routed file (proves per-occurrence teeth)", () => {
    const filler = Array.from({ length: PROXIMITY_WINDOW + 5 }, (_, i) => `    // filler line ${i}`).join("\n");
    const synthetic = [
      "function routedHandler(log) {",
      "  const verdict = await log.getAuditChainVerdict();",
      "  return auditChainVerdictClaimsClean(verdict);",
      "}",
      filler,
      "function bypassingHandler(res) {",
      "  // derives clean straight off the routine count, skipping the sealed verdict",
      "  const clean = res.integrity_findings.length === 0;",
      "  return { chain_ok: clean };",
      "}",
    ].join("\n");

    const flagged = unroutedOccurrences(synthetic);
    expect(flagged.length, "the bypass must be caught").toBe(1);
    expect(flagged[0]!.signal).toBe("integrity_findings.length");
    expect(flagged[0]!.snippet).toContain("res.integrity_findings.length === 0");
  });

  // Round-5 teeth (two-family gate): the laundering idioms both reviewers
  // exploited must each be flagged when unrouted, alias-minting, destructuring,
  // and filter-emptiness. The alias's LATER use (`f.length === 0`) is invisible
  // to a line scan; the mint line is the enforcement point, so flagging the mint
  // forces routing/exemption exactly where the raw signal enters scope.
  it("flags the alias-mint, destructure, and filter-emptiness laundering idioms", () => {
    const alias = unroutedOccurrences(
      [
        "function bypass(res) {",
        "  const f = res.integrity_findings;",
        "  return { chain_ok: f.filter(Boolean).length === 0 };",
        "}",
      ].join("\n"),
    );
    expect(alias.length, "the alias mint must be flagged").toBeGreaterThanOrEqual(1);
    expect(alias[0]!.signal).toBe("integrity_findings alias-mint");

    const destructured = unroutedOccurrences(
      [
        "function bypass2(res) {",
        "  const { integrity_findings } = res;",
        "  return { chain_ok: integrity_findings.length === 0 };",
        "}",
      ].join("\n"),
    );
    expect(
      destructured.some((o) => o.signal === "integrity_findings destructure"),
      "the destructure must be flagged",
    ).toBe(true);

    const filtered = unroutedOccurrences(
      [
        "function bypass3(res) {",
        "  return { chain_ok: res.integrity_findings.filter(isReal).length === 0 };",
        "}",
      ].join("\n"),
    );
    expect(filtered.length, "the filter-emptiness idiom must be flagged").toBe(1);
    expect(filtered[0]!.signal).toBe("integrity_findings.filter");
  });

  // The negative-control's counterpart: once the bypass routes (or is exempted),
  // the SAME checker is clean. Proves the guard is satisfiable the honest way and
  // does not false-positive on a genuinely-routed occurrence.
  it("passes the same file once the bypass routes through the chokepoint", () => {
    const filler = Array.from({ length: PROXIMITY_WINDOW + 5 }, (_, i) => `    // filler line ${i}`).join("\n");
    const routedFix = [
      "function routedHandler(log) {",
      "  const verdict = await log.getAuditChainVerdict();",
      "  return auditChainVerdictClaimsClean(verdict);",
      "}",
      filler,
      "function nowRoutedHandler(log) {",
      "  const verdict = await log.getAuditChainVerdict();",
      "  const clean = auditChainVerdictClaimsClean(verdict);",
      "  return { chain_ok: clean };",
      "}",
    ].join("\n");
    expect(unroutedOccurrences(routedFix)).toEqual([]);

    const exemptedFix = [
      "function denyOnFinding(res) {",
      "  // audit-chokepoint-exempt: fail-closed deny, never stamps a clean label",
      "  if (res.integrity_findings.length > 0) return deny();",
      "  return ok();",
      "}",
    ].join("\n");
    expect(unroutedOccurrences(exemptedFix)).toEqual([]);
  });

  // No hardcoded green: a literal `chain_verified: true` / `chain_verdict:
  // "verified"` is a claim that never passed through the verdict. Forbid it
  // everywhere (the honest producer computes the boolean from the helper).
  it("no source hardcodes a green audit-chain claim", () => {
    const literalGreen = /chain_verified\s*[:=]\s*true|chain_verdict\s*[:=]\s*["']verified["']/;
    const offenders = files.filter((f) => literalGreen.test(f.text)).map((f) => f.rel);
    expect(offenders, "hardcoded green audit-chain claim; derive it from the shared verdict instead").toEqual([]);
  });

  // Positive registry: the known producer surfaces that COMPUTE an audit-chain
  // cleanliness verdict must each reference the chokepoint. If a refactor strips
  // the routing out of any of these, this fails loudly (the negative scans above
  // could be silently satisfied by also deleting the raw-signal reference).
  it("every known cleanliness-producing surface references the chokepoint", () => {
    const PRODUCERS = [
      "principal-policy/posture.ts",
      "principal-policy/posture-routes.ts",
      "principal-policy/feature-health.ts",
      "dashboard/aggregator.ts",
      "agent-native/cooperative-surface.ts",
      "audit/tools.ts",
      "cli/castle-wall.ts",
    ];
    for (const p of PRODUCERS) {
      const f = files.find((x) => x.rel === p);
      expect(f, `expected producer surface ${p} to exist`).toBeDefined();
      const routed = ROUTING_SYMBOLS.some((s) => f!.text.includes(s));
      expect(
        routed,
        `${p} must route its audit-chain cleanliness claim through the shared verdict ` +
          `(one of: ${ROUTING_SYMBOLS.join(", ")})`,
      ).toBe(true);
    }
  });
});
