import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { PROTECTION_HERO_COPY } from "../../src/egress-gate/protection-claim.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");
const CHOKEPOINT = "server/src/egress-gate/protection-claim.ts";
const FROZEN_DASHBOARD_HERO = "server/src/dashboard/html.ts";
const CHOKEPOINT_SOURCE_TEXT = readFileSync(join(REPO_ROOT, CHOKEPOINT), "utf8");

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

function propertyNameText(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

function findProtectionStateAdviceFunction(
  source: ts.SourceFile,
): ts.FunctionDeclaration {
  let found: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node): void => {
    if (
      ts.isFunctionDeclaration(node) &&
      node.name?.text === "protectionStateAdvice"
    ) {
      found = node;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  if (found === undefined || found.body === undefined) {
    throw new Error("protectionStateAdvice function not found");
  }
  return found;
}

function resolveAdvicePhraseExpression(
  expression: ts.Expression,
  localStrings: ReadonlyMap<string, string>,
  source: ts.SourceFile,
  unresolved: string[],
): string | undefined {
  const flattened = flattenConcat(expression);
  if (flattened !== undefined) return flattened;
  if (ts.isIdentifier(expression)) {
    const value = localStrings.get(expression.text);
    if (value !== undefined) return value;
    unresolved.push(expression.getText(source));
    return undefined;
  }
  if (
    ts.isPropertyAccessExpression(expression) &&
    ts.isIdentifier(expression.expression) &&
    expression.expression.text === "PROTECTION_HERO_COPY"
  ) {
    const heroCopy = PROTECTION_HERO_COPY as Readonly<Record<string, string>>;
    const value = heroCopy[expression.name.text];
    if (value !== undefined) return value;
  }
  if (expression.kind === ts.SyntaxKind.NullKeyword) return undefined;
  unresolved.push(expression.getText(source));
  return undefined;
}

function extractProtectionStateAdvicePhrases(sourceText: string): {
  phrases: string[];
  unresolved: string[];
} {
  const source = ts.createSourceFile(
    CHOKEPOINT,
    sourceText,
    ts.ScriptTarget.ESNext,
    true,
  );
  const advice = findProtectionStateAdviceFunction(source);
  const localStrings = new Map<string, string>();
  for (const statement of advice.body!.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.initializer === undefined) {
        continue;
      }
      const value = flattenConcat(declaration.initializer);
      if (value !== undefined) localStrings.set(declaration.name.text, value);
    }
  }

  const phrases = new Set<string>(Object.values(PROTECTION_HERO_COPY));
  const unresolved: string[] = [];
  const advicePhraseProperties = new Set([
    "operatorSentence",
    "castleWallLabel",
    "imperative",
  ]);

  const visit = (node: ts.Node): void => {
    if (
      ts.isReturnStatement(node) &&
      node.expression !== undefined &&
      ts.isObjectLiteralExpression(node.expression)
    ) {
      for (const property of node.expression.properties) {
        if (!ts.isPropertyAssignment(property)) continue;
        const propertyName = propertyNameText(property.name);
        if (
          propertyName === undefined ||
          !advicePhraseProperties.has(propertyName)
        ) {
          continue;
        }
        const phrase = resolveAdvicePhraseExpression(
          property.initializer,
          localStrings,
          source,
          unresolved,
        );
        if (phrase !== undefined) phrases.add(phrase);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(advice.body);

  return {
    phrases: [...phrases].sort(),
    unresolved: [...new Set(unresolved)].sort(),
  };
}

const PROTECTION_PROSE_EXTRACTION =
  extractProtectionStateAdvicePhrases(CHOKEPOINT_SOURCE_TEXT);
const PROTECTION_PROSE = PROTECTION_PROSE_EXTRACTION.phrases;

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

  it("derives every current protectionStateAdvice phrase from the advice source", () => {
    expect(PROTECTION_PROSE_EXTRACTION.unresolved).toEqual([]);
    expect(PROTECTION_PROSE).toContain(PROTECTION_HERO_COPY.green);
    expect(PROTECTION_PROSE).toContain(PROTECTION_HERO_COPY.nonGreen);
    expect(PROTECTION_PROSE).toContain("Castle Wall Full");
    expect(PROTECTION_PROSE).toContain(
      "Castle Wall status unknown (exclusive-egress boot re-park failed)",
    );
  });

  it("would fail registration for an injected advice phrase", () => {
    const injected = CHOKEPOINT_SOURCE_TEXT.replace(
      "  switch (claim.state) {",
      `  if (claim.basis === "synthetic_unregistered") {
    return {
      green: true,
      operatorSentence: "Your agent is fully protected and sealed.",
      castleWallLabel: "Castle Wall Fortified",
      imperative: null,
    };
  }
  switch (claim.state) {`,
    );
    expect(injected).not.toEqual(CHOKEPOINT_SOURCE_TEXT);

    const extraction = extractProtectionStateAdvicePhrases(injected);
    const extra = extraction.phrases.filter(
      (phrase) => !PROTECTION_PROSE.includes(phrase),
    );

    expect(extraction.unresolved).toEqual([]);
    expect(extra.sort()).toEqual([
      "Castle Wall Fortified",
      "Your agent is fully protected and sealed.",
    ]);
  });
});
