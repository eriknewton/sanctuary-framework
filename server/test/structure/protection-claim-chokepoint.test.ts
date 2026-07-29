import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import {
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND,
  EGRESS_GATE_STAND_DOWN_EFFECT,
  GENERIC_UID_CONFINEMENT_REMEDY,
} from "../../src/egress-gate/operator-advice.js";
import { PROTECTION_HERO_COPY } from "../../src/egress-gate/protection-claim.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");
const CHOKEPOINT = "server/src/egress-gate/protection-claim.ts";
const GENERIC_ADVICE_OWNER = "server/src/egress-gate/operator-advice.ts";
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

function staticStringExpression(
  expression: ts.Expression,
  knownStrings: ReadonlyMap<string, string>,
): string | undefined {
  if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
    return expression.text;
  }
  if (ts.isParenthesizedExpression(expression)) {
    return staticStringExpression(expression.expression, knownStrings);
  }
  if (ts.isIdentifier(expression)) {
    return knownStrings.get(expression.text);
  }
  if (
    ts.isBinaryExpression(expression) &&
    expression.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    const left = staticStringExpression(expression.left, knownStrings);
    const right = staticStringExpression(expression.right, knownStrings);
    return left !== undefined && right !== undefined ? left + right : undefined;
  }
  if (ts.isTemplateExpression(expression)) {
    let out = expression.head.text;
    for (const span of expression.templateSpans) {
      const value = staticStringExpression(span.expression, knownStrings);
      if (value === undefined) return undefined;
      out += value + span.literal.text;
    }
    return out;
  }
  return undefined;
}

function propertyNameText(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

function expressionName(expression: ts.Expression): string | undefined {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return undefined;
}

function objectLiteralHasProperty(
  object: ts.ObjectLiteralExpression,
  property: string,
): boolean {
  return object.properties.some((p) => {
    if (!ts.isPropertyAssignment(p) && !ts.isShorthandPropertyAssignment(p)) {
      return false;
    }
    return propertyNameText(p.name) === property;
  });
}

function objectLiteralPropertyAssignment(
  object: ts.ObjectLiteralExpression,
  property: string,
): ts.PropertyAssignment | undefined {
  for (const candidate of object.properties) {
    if (
      ts.isPropertyAssignment(candidate) &&
      propertyNameText(candidate.name) === property
    ) {
      return candidate;
    }
  }
  return undefined;
}

function containsFortressScopedMode(node: ts.Node): boolean {
  let found = false;
  const visit = (candidate: ts.Node): void => {
    if (found) return;
    const initializer = ts.isPropertyAssignment(candidate)
      ? ts.isAsExpression(candidate.initializer)
        ? candidate.initializer.expression
        : candidate.initializer
      : undefined;
    if (
      ts.isPropertyAssignment(candidate) &&
      propertyNameText(candidate.name) === "mode" &&
      initializer !== undefined &&
      ts.isStringLiteral(initializer) &&
      initializer.text === "fortress_scoped"
    ) {
      found = true;
      return;
    }
    ts.forEachChild(candidate, visit);
  };
  visit(node);
  return found;
}

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isSatisfiesExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function isInputPurposeCoarseWallCheck(
  expression: ts.Expression,
  source: ts.SourceFile,
): boolean {
  const unwrapped = unwrapExpression(expression);
  if (
    !ts.isBinaryExpression(unwrapped) ||
    unwrapped.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsEqualsToken
  ) {
    return false;
  }
  const left = unwrapExpression(unwrapped.left);
  const right = unwrapExpression(unwrapped.right);
  const matches = (a: ts.Expression, b: ts.Expression): boolean =>
    ts.isPropertyAccessExpression(a) &&
    a.getText(source) === "input.purpose" &&
    ts.isStringLiteral(b) &&
    b.text === "coarse-wall";
  return matches(left, right) || matches(right, left);
}

function isEmptyObjectLiteral(expression: ts.Expression): boolean {
  const unwrapped = unwrapExpression(expression);
  return ts.isObjectLiteralExpression(unwrapped) && unwrapped.properties.length === 0;
}

function hasStructurallyGatedCoarseWallSubjectMode(
  object: ts.ObjectLiteralExpression,
  source: ts.SourceFile,
): boolean {
  return object.properties.some((property) => {
    if (!ts.isSpreadAssignment(property)) return false;
    const spread = unwrapExpression(property.expression);
    if (!ts.isConditionalExpression(spread)) return false;
    if (!isInputPurposeCoarseWallCheck(spread.condition, source)) return false;
    if (!isEmptyObjectLiteral(spread.whenFalse)) return false;
    const whenTrue = unwrapExpression(spread.whenTrue);
    if (!ts.isObjectLiteralExpression(whenTrue)) return false;
    const subjectMode = objectLiteralPropertyAssignment(
      whenTrue,
      "protectionSubjectMatchMode",
    );
    return (
      subjectMode !== undefined &&
      containsFortressScopedMode(subjectMode.initializer)
    );
  });
}

function expressionMightBeBareFortressId(
  expression: ts.Expression,
  source: ts.SourceFile,
): boolean {
  const text = expression.getText(source);
  return (
    text === "fortressId" ||
    text.endsWith(".fortressId") ||
    text.includes("fortressIdFromStoragePath(")
  );
}

function isAllowedCoarseWallFortressScopedCall(
  fileName: string,
  call: ts.CallExpression,
  source: ts.SourceFile,
): boolean {
  if (fileName !== "server/src/wrap/cli.ts") return false;
  if (expressionName(call.expression) !== "buildFeatureHealthPanel") return false;
  const first = call.arguments[0];
  return (
    first !== undefined &&
    ts.isObjectLiteralExpression(first) &&
    hasStructurallyGatedCoarseWallSubjectMode(first, source)
  );
}

function findProtectionSubjectScopeViolations(
  fileName: string,
  sourceText: string,
): string[] {
  const source = ts.createSourceFile(
    fileName,
    sourceText,
    ts.ScriptTarget.ESNext,
    true,
  );
  const builders = new Set([
    "buildCastleWallPosture",
    "buildAuditDigest",
    "buildFeatureHealthPanel",
  ]);
  const offenders: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const name = expressionName(node.expression);
      const first = node.arguments[0];
      if (
        name !== undefined &&
        builders.has(name) &&
        first !== undefined &&
        ts.isObjectLiteralExpression(first)
      ) {
        const { line } = source.getLineAndCharacterOfPosition(
          node.getStart(source),
        );
        const hasFortressScoped = containsFortressScopedMode(first);
        if (
          hasFortressScoped &&
          !isAllowedCoarseWallFortressScopedCall(fileName, node, source)
        ) {
          offenders.push(
            `${fileName}:${line + 1} ${name} passes fortress_scoped outside the coarse-wall probe`,
          );
        }

        const subject = objectLiteralPropertyAssignment(
          first,
          "protectionClaimSubject",
        );
        if (
          subject !== undefined &&
          expressionMightBeBareFortressId(subject.initializer, source) &&
          !hasFortressScoped
        ) {
          offenders.push(
            `${fileName}:${line + 1} ${name} passes a bare fortress id as protectionClaimSubject`,
          );
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return offenders;
}

function findProtectionSubjectOmissions(
  fileName: string,
  sourceText: string,
): string[] {
  const source = ts.createSourceFile(
    fileName,
    sourceText,
    ts.ScriptTarget.ESNext,
    true,
  );
  const builders = new Set([
    "buildCastleWallPosture",
    "buildAuditDigest",
    "buildFeatureHealthPanel",
  ]);
  const offenders: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const name = expressionName(node.expression);
      if (name !== undefined && builders.has(name)) {
        const first = node.arguments[0];
        const hasSubject =
          first !== undefined &&
          ts.isObjectLiteralExpression(first) &&
          objectLiteralHasProperty(first, "protectionClaimSubject");
        if (!hasSubject) {
          const { line } = source.getLineAndCharacterOfPosition(
            node.getStart(source),
          );
          offenders.push(
            `${fileName}:${line + 1} ${name} omits protectionClaimSubject`,
          );
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return offenders;
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
  const resolvedStatic = staticStringExpression(expression, localStrings);
  if (resolvedStatic !== undefined) return resolvedStatic;
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
  const localStrings = new Map<string, string>([
    ["EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND", EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND],
    ["EGRESS_GATE_STAND_DOWN_EFFECT", EGRESS_GATE_STAND_DOWN_EFFECT],
    ["GENERIC_UID_CONFINEMENT_REMEDY", GENERIC_UID_CONFINEMENT_REMEDY],
  ]);
  for (const statement of advice.body!.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.initializer === undefined) {
        continue;
      }
      const value = staticStringExpression(declaration.initializer, localStrings);
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
      node.expression !== undefined
    ) {
      if (!ts.isObjectLiteralExpression(node.expression)) {
        unresolved.push(node.expression.getText(source));
        ts.forEachChild(node, visit);
        return;
      }
      for (const property of node.expression.properties) {
        if (!ts.isPropertyAssignment(property)) {
          unresolved.push(property.getText(source));
          continue;
        }
        const propertyName = propertyNameText(property.name);
        if (propertyName === undefined) {
          unresolved.push(property.name.getText(source));
          continue;
        }
        if (!advicePhraseProperties.has(propertyName)) {
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
  if (phrase === GENERIC_UID_CONFINEMENT_REMEDY) {
    allowed.add(GENERIC_ADVICE_OWNER);
  }
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

  it("every production posture/feature-health/digest caller supplies protectionClaimSubject", () => {
    const violations: string[] = [];
    for (const file of tsFiles(SERVER_SRC)) {
      const rel = relative(REPO_ROOT, file);
      const source = readFileSync(file, "utf8");
      violations.push(...findProtectionSubjectOmissions(rel, source));
      violations.push(...findProtectionSubjectScopeViolations(rel, source));
    }
    expect(violations).toEqual([]);
  });

  it("structural guard rejects per-agent fortress_scoped and bare fortress subjects", () => {
    const source = `
      buildCastleWallPosture({
        auditLog,
        originMachine,
        protectionClaimSubject: fortressIdFromStoragePath(storagePath),
      });
      buildFeatureHealthPanel({
        auditLog,
        originMachine,
        protectionClaimSubject,
        protectionSubjectMatchMode: { mode: "fortress_scoped", fortressId },
      });
    `;

    expect(findProtectionSubjectScopeViolations("synthetic.ts", source)).toEqual([
      "synthetic.ts:2 buildCastleWallPosture passes a bare fortress id as protectionClaimSubject",
      "synthetic.ts:7 buildFeatureHealthPanel passes fortress_scoped outside the coarse-wall probe",
    ]);
  });

  it("structural guard does not allow fortress_scoped from spoofed coarse-wall text", () => {
    const source = `
      buildFeatureHealthPanel({
        auditLog,
        originMachine,
        protectionClaimSubject,
        protectionSubjectMatchMode: { mode: "fortress_scoped", fortressId },
        note: 'input.purpose === "coarse-wall" protectionSubjectMatchMode',
      });
    `;

    expect(
      findProtectionSubjectScopeViolations(
        "server/src/wrap/cli.ts",
        source,
      ),
    ).toEqual([
      "server/src/wrap/cli.ts:2 buildFeatureHealthPanel passes fortress_scoped outside the coarse-wall probe",
    ]);
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

  it("fails closed when advice phrase extraction cannot model the return shape", () => {
    const injectedBranches = [
      `  if (claim.basis === "synthetic_spread") {
    return {
      green: true,
      ...{
        operatorSentence: "Your agent is fully protected and sealed.",
        castleWallLabel: "Castle Wall Fortified",
        imperative: null,
      },
    };
  }
`,
      `  if (claim.basis === "synthetic_variable") {
    const advice = {
      green: true,
      operatorSentence: "Your agent is fully protected and sealed.",
      castleWallLabel: "Castle Wall Fortified",
      imperative: null,
    };
    return advice;
  }
`,
      `  if (claim.basis === "synthetic_ternary") {
    return claim.state === "exclusive"
      ? {
          green: true,
          operatorSentence: "Your agent is fully protected and sealed.",
          castleWallLabel: "Castle Wall Fortified",
          imperative: null,
        }
      : {
          green: false,
          operatorSentence: "Protection not confirmed.",
          castleWallLabel: "Castle Wall status unknown (not confirmed armed)",
          imperative: null,
        };
  }
`,
      `  if (claim.basis === "synthetic_computed") {
    return {
      green: true,
      ["operatorSentence"]: "Your agent is fully protected and sealed.",
      castleWallLabel: "Castle Wall Fortified",
      imperative: null,
    };
  }
`,
      `  if (claim.basis === "synthetic_shorthand") {
    const operatorSentence = "Your agent is fully protected and sealed.";
    return {
      green: true,
      operatorSentence,
      castleWallLabel: "Castle Wall Fortified",
      imperative: null,
    };
  }
`,
    ];

    for (const branch of injectedBranches) {
      const injected = CHOKEPOINT_SOURCE_TEXT.replace(
        "  switch (claim.state) {",
        `${branch}  switch (claim.state) {`,
      );
      expect(injected).not.toEqual(CHOKEPOINT_SOURCE_TEXT);
      expect(extractProtectionStateAdvicePhrases(injected).unresolved).not.toEqual([]);
    }
  });
});
