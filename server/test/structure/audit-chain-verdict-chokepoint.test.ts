/**
 * F2 BLOCKER-1 (adversarial re-gate round 3, 2026-07-14) ANTI-REGRESSION.
 *
 * The round-1/2 fix routed the sealed-region verdict into cleanliness claims
 * per-surface, which is whack-a-mole: a future surface (or a resurrected old
 * one) can compute "the audit chain is verified/clean" straight off
 * `integrity_findings.length` or a raw `chain_verified` boolean and skip the
 * sealed-region crypto verdict the operator hot-path deliberately omits. Round 3
 * collapsed the decision into ONE chokepoint, `AuditLog.getAuditChainVerdict()`
 * (folded via `auditChainVerdictClaimsClean` / `auditChainVerdictUntampered`).
 *
 * This structural test fails if any source file derives an audit-chain
 * cleanliness verdict WITHOUT going through that chokepoint. It is deliberately
 * source-text-based (not a runtime test) so it catches the bypass at authoring
 * time, before any fortress is even constructed.
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
// A bespoke sealed check cannot produce an `AuditChainVerdict` without one of
// these, so referencing one is the structural proof of routing.
const ROUTING_SYMBOLS = [
  "getAuditChainVerdict",
  "auditChainVerdictClaimsClean",
  "auditChainVerdictUntampered",
];
const isRouted = (text: string): boolean => ROUTING_SYMBOLS.some((s) => text.includes(s));

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

  // The exact bypass the gate named: deriving verified/clean from the raw
  // routine-findings count. Any file that reads `integrity_findings.length`
  // MUST also route through the chokepoint (which folds the sealed verdict the
  // routine findings omit), or be the chokepoint's own home.
  it("no file derives cleanliness from integrity_findings.length without the chokepoint", () => {
    const offenders = files
      .filter((f) => f.rel !== CHOKEPOINT_HOME)
      .filter((f) => f.text.includes("integrity_findings.length"))
      .filter((f) => !isRouted(f.text))
      .filter((f) => !(f.rel in CONSUMER_EXEMPT))
      .map((f) => f.rel);
    expect(
      offenders,
      "these files read integrity_findings.length but never call getAuditChainVerdict; " +
        "route the cleanliness claim through the shared verdict (it folds the sealed-region " +
        "crypto verdict the routine findings skip) or, if genuinely a renderer/neutral surface, " +
        "add it to CONSUMER_EXEMPT with a reason:\n" +
        offenders.join("\n"),
    ).toEqual([]);
  });

  // The "verified against the audit chain" label is a cleanliness claim; it may
  // only be emitted where the verdict was consulted.
  it("no file emits the verified_against_audit_chain label without the chokepoint", () => {
    const offenders = files
      .filter((f) => f.rel !== CHOKEPOINT_HOME)
      .filter((f) => f.text.includes("verified_against_audit_chain"))
      .filter((f) => !isRouted(f.text))
      .filter((f) => !(f.rel in CONSUMER_EXEMPT))
      .map((f) => f.rel);
    expect(offenders, `these files stamp verified_against_audit_chain without routing through ${CHOKEPOINT}`).toEqual([]);
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
      expect(
        isRouted(f!.text),
        `${p} must route its audit-chain cleanliness claim through the shared verdict ` +
          `(one of: ${ROUTING_SYMBOLS.join(", ")})`,
      ).toBe(true);
    }
  });
});
