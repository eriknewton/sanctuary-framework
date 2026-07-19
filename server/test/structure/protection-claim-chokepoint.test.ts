import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import {
  PROTECTION_HERO_COPY,
  protectionStateAdvice,
  protectionStateClaimFromObservation,
  type ProtectionStateObservation,
} from "../../src/egress-gate/protection-claim.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");

const PROTECTION_PROSE = [
  PROTECTION_HERO_COPY.green,
  PROTECTION_HERO_COPY.nonGreen,
  "Your agent is wrapped, but only coarse Castle Wall enforcement is confirmed.",
  "Your agent is wrapped, but enforcement is not confirmed.",
  "Your agent is wrapped, but enforcement state is not confirmed.",
  "Your agent is wrapped, but exclusive-egress boot re-park is not confirmed.",
  "Castle Wall Full",
  "Castle Wall coarse-only (fine-grained egress not live)",
  "Castle Wall NOT ARMED (traffic not filtered)",
  "Castle Wall status unknown (not confirmed armed)",
  "Castle Wall status unknown (daemon heartbeat missing; traffic may be blocked)",
  "Castle Wall status unknown (exclusive-egress boot re-park failed)",
  "Run 'sanctuary castle-wall status' to inspect live enforcement before relying on this wrap.",
  "Run 'sudo sanctuary protect --repair-egress-gate' to repair fine-grained exclusive egress.",
] as const;

const CHOKEPOINT = "server/src/egress-gate/protection-claim.ts";
const FROZEN_DASHBOARD_HERO = "server/src/dashboard/html.ts";

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

function normalizeProtectionProse(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

function flattenConcat(node: ts.Node): string | undefined {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return node.text;
  }
  if (ts.isParenthesizedExpression(node)) {
    return flattenConcat(node.expression);
  }
  if (
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    const left = flattenConcat(node.left);
    const right = flattenConcat(node.right);
    return left !== undefined && right !== undefined ? left + right : undefined;
  }
  return undefined;
}

function scanProtectionProse(fileName: string, sourceText: string): string[] {
  const patterns = PROTECTION_PROSE.map((phrase) => ({
    phrase,
    needle: normalizeProtectionProse(phrase),
  }));
  const source = ts.createSourceFile(
    fileName,
    sourceText,
    ts.ScriptTarget.ESNext,
    true,
  );
  const offenders: string[] = [];
  const seen = new Set<string>();

  const check = (text: string, node: ts.Node): void => {
    const normalized = normalizeProtectionProse(text);
    for (const { phrase, needle } of patterns) {
      if (!normalized.includes(needle)) continue;
      const { line } = source.getLineAndCharacterOfPosition(node.getStart(source));
      const offence = `${fileName}:${line + 1} contains protection prose ${JSON.stringify(phrase)}`;
      if (!seen.has(offence)) {
        seen.add(offence);
        offenders.push(offence);
      }
    }
  };

  const visit = (node: ts.Node): void => {
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node)
    ) {
      check(node.text, node);
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.PlusToken
    ) {
      const flattened = flattenConcat(node);
      if (flattened !== undefined) check(flattened, node);
    }
    ts.forEachChild(node, visit);
  };

  visit(source);
  return offenders;
}

function allowedFilesFor(phrase: string): Set<string> {
  const allowed = new Set([CHOKEPOINT]);
  if (phrase === "Your agent is protected.") {
    // Frozen dashboard token: server/reorg-surface-manifest.md protects this
    // exact HERO_COPY string and id="hero-copy". Dashboard HTML tests prove it
    // renders only when the snapshot is green.
    allowed.add(FROZEN_DASHBOARD_HERO);
  }
  return allowed;
}

describe("protection-state claim chokepoint", () => {
  it("keeps wrap-banner and dashboard-hero protection prose in the claim chokepoint", () => {
    // Parser-based, case-folded, and whitespace-collapsing. It catches string
    // literals, no-substitution templates, static template spans, and literal
    // concatenations. It still cannot catch runtime lookup tables, template
    // substitutions, or synonyms that do not contain one of these phrases.
    //
    // Scope: this guard covers the wrap success banner and legacy dashboard
    // hero copy. `principal-policy/posture-home-html.ts` is a separate posture
    // dashboard renderer with its own basis-derived vocabulary; this test does
    // not claim that surface is routed through this chokepoint.
    const violations: string[] = [];
    for (const file of tsFiles(SERVER_SRC)) {
      const rel = relative(REPO_ROOT, file);
      const source = readFileSync(file, "utf8");
      for (const offence of scanProtectionProse(rel, source)) {
        const phrase = PROTECTION_PROSE.find((p) =>
          offence.includes(JSON.stringify(p)),
        );
        if (phrase !== undefined && !allowedFilesFor(phrase).has(rel)) {
          violations.push(offence);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("catches case, wrapped, and split protection prose forms", () => {
    const samples = [
      'const s = "your agent is PROTECTED.";',
      "const s = `Castle Wall\\nFull`;",
      'const s = "Castle " + "Wall NOT ARMED (traffic not filtered)";',
    ];
    for (const source of samples) {
      expect(scanProtectionProse("synthetic.ts", source)).not.toEqual([]);
    }
  });

  it("registers every current protectionStateAdvice phrase", () => {
    const observations: ProtectionStateObservation[] = [
      { state: "exclusive", basis: "exclusive_egress_observed" },
      { state: "coarse-only", basis: "exclusive_egress_cap_observed" },
      { state: "unprotected", basis: "disarm_observed_off" },
      {
        state: "unknown",
        basis: "insufficient_evidence",
        reasons: ["test"],
      },
      {
        state: "unknown",
        basis: "daemon_liveness_missing",
        reasons: ["test"],
      },
      {
        state: "unknown",
        basis: "exclusive_egress_repark_failed",
        reasons: ["test"],
      },
    ];
    const actual = new Set<string>([
      PROTECTION_HERO_COPY.green,
      PROTECTION_HERO_COPY.nonGreen,
    ]);
    for (const observation of observations) {
      const advice = protectionStateAdvice(
        protectionStateClaimFromObservation(observation),
      );
      actual.add(advice.operatorSentence);
      actual.add(advice.castleWallLabel);
      if (advice.imperative !== null) actual.add(advice.imperative);
    }

    expect([...actual].sort()).toEqual([...PROTECTION_PROSE].sort());
  });
});
