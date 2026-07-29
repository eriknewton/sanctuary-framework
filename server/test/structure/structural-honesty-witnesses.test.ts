import { readFileSync, readdirSync } from "node:fs";
import { join, posix, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import ts from "typescript";

import { STRUCTURAL_HONESTY_CLAIM_IDS } from "../../src/claim-witness.js";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");
const CLAIM_WITNESS = "server/src/claim-witness.ts";
const CLAIM_BASIS = "server/src/egress-gate/claim-basis.ts";

function readSource(repoRelative: string): string {
  return readFileSync(join(REPO_ROOT, repoRelative), "utf8");
}

function tsFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return tsFiles(full);
    return entry.isFile() && entry.name.endsWith(".ts") ? [full] : [];
  });
}

function repoRelative(full: string): string {
  return relative(REPO_ROOT, full).split("/").join("/");
}

type WitnessHelper = "observing" | "verifiedEmptyFrom";

interface ParsedSource {
  rel: string;
  source: string;
  ast: ts.SourceFile;
}

function parseSource(rel: string, source: string): ts.SourceFile {
  return ts.createSourceFile(rel, source, ts.ScriptTarget.ESNext, true, ts.ScriptKind.TS);
}

function stringLiteralValue(node: ts.Node | undefined): string | undefined {
  if (node === undefined) return undefined;
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
    ? node.text
    : undefined;
}

function expectedHelper(id: string): WitnessHelper {
  return id === "evidence-pack.inventory.empty-verified"
    ? "verifiedEmptyFrom"
    : "observing";
}

function allowedLiteralHelpers(id: string): readonly WitnessHelper[] {
  return id === "observe.candidate-census"
    ? ["observing", "verifiedEmptyFrom"]
    : [expectedHelper(id)];
}

function isHelperCall(node: ts.Node, helper: WitnessHelper): node is ts.CallExpression {
  return (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === helper
  );
}

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

const WITNESS_BRAND_NAMES = new Set(["Observed", "VerifiedEmpty"]);

function entityNameText(name: ts.EntityName): string {
  return ts.isIdentifier(name)
    ? name.text
    : `${entityNameText(name.left)}.${name.right.text}`;
}

function lastEntitySegment(name: string): string {
  const parts = name.split(".");
  return parts[parts.length - 1] ?? name;
}

function typeNodeNamesWitnessBrand(typeNode: ts.TypeNode): boolean {
  let namesWitnessBrand = false;
  const visit = (node: ts.Node): void => {
    if (ts.isTypeReferenceNode(node)) {
      const name = lastEntitySegment(entityNameText(node.typeName));
      if (WITNESS_BRAND_NAMES.has(name)) {
        namesWitnessBrand = true;
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(typeNode);
  return namesWitnessBrand;
}

function moduleSpecifierTargetsClaimWitness(fromRel: string, specifier: string): boolean {
  if (!specifier.startsWith(".")) return false;
  const withoutExtension = specifier.replace(/\.(?:c|m)?(?:j|t)sx?$/, "");
  return posix.normalize(posix.join(posix.dirname(fromRel), withoutExtension)) ===
    "server/src/claim-witness";
}

function importTypeNamesWitnessBrand(
  fromRel: string,
  node: ts.ImportTypeNode,
): boolean {
  const literal = node.argument.literal;
  if (!ts.isStringLiteral(literal)) return false;
  if (!moduleSpecifierTargetsClaimWitness(fromRel, literal.text)) return false;
  const qualifier = node.qualifier;
  if (qualifier === undefined) return false;
  return WITNESS_BRAND_NAMES.has(lastEntitySegment(entityNameText(qualifier)));
}

function typeNodeImportsWitnessBrand(fromRel: string, typeNode: ts.TypeNode): boolean {
  let importsWitnessBrand = false;
  const visit = (node: ts.Node): void => {
    if (ts.isImportTypeNode(node) && importTypeNamesWitnessBrand(fromRel, node)) {
      importsWitnessBrand = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(typeNode);
  return importsWitnessBrand;
}

function isLiteralExpression(node: ts.Expression): boolean {
  if (
    ts.isStringLiteral(node) ||
    ts.isNoSubstitutionTemplateLiteral(node) ||
    ts.isNumericLiteral(node) ||
    node.kind === ts.SyntaxKind.TrueKeyword ||
    node.kind === ts.SyntaxKind.FalseKeyword ||
    node.kind === ts.SyntaxKind.NullKeyword
  ) {
    return true;
  }
  return (
    ts.isPrefixUnaryExpression(node) &&
    (node.operator === ts.SyntaxKind.PlusToken || node.operator === ts.SyntaxKind.MinusToken) &&
    ts.isNumericLiteral(node.operand)
  );
}

function isPromiseSettledFactory(node: ts.CallExpression): boolean {
  return (
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === "Promise" &&
    (node.expression.name.text === "resolve" || node.expression.name.text === "reject")
  );
}

function isPureLiteralWrapperCall(node: ts.CallExpression): boolean {
  return (
    ts.isIdentifier(node.expression) &&
    ["Boolean", "Number", "String"].includes(node.expression.text) &&
    node.arguments.length === 1 &&
    isLiteralExpression(node.arguments[0]!)
  );
}

function isQualifyingObservationCall(node: ts.CallExpression): boolean {
  return !isPromiseSettledFactory(node) && !isPureLiteralWrapperCall(node);
}

function observingCallbackCanObserve(callback: ts.Expression | undefined): boolean {
  if (
    callback === undefined ||
    (!ts.isArrowFunction(callback) && !ts.isFunctionExpression(callback))
  ) {
    return false;
  }
  let canObserve = false;
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && isQualifyingObservationCall(node)) {
      canObserve = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(callback.body);
  return canObserve;
}

describe("structural honesty witnesses", () => {
  it("keeps Observed and VerifiedEmpty brands minted only by the witness module", () => {
    const offenders: string[] = [];
    for (const full of tsFiles(SERVER_SRC)) {
      const rel = repoRelative(full);
      if (rel === CLAIM_WITNESS) continue;
      const source = readFileSync(full, "utf8");
      if (/\bas\s+(?:Observed|VerifiedEmpty)\b/.test(source)) {
        offenders.push(`${rel}: direct witness-brand cast`);
      }
      const ast = parseSource(rel, source);
      const visit = (node: ts.Node): void => {
        if (ts.isImportTypeNode(node) && importTypeNamesWitnessBrand(rel, node)) {
          offenders.push(`${rel}:${lineOf(ast, node)} import-type witness-brand reference`);
          return;
        }
        if (
          ts.isSatisfiesExpression(node) &&
          (typeNodeNamesWitnessBrand(node.type) || typeNodeImportsWitnessBrand(rel, node.type))
        ) {
          offenders.push(`${rel}:${lineOf(ast, node)} witness-brand satisfies expression`);
          return;
        }
        ts.forEachChild(node, visit);
      };
      visit(ast);
    }
    expect(offenders).toEqual([]);
  });

  it("routes every structural-honesty claim id through its witness constructor", () => {
    const srcFiles = tsFiles(SERVER_SRC)
      .map((full): ParsedSource => {
        const rel = repoRelative(full);
        const source = readFileSync(full, "utf8");
        return { rel, source, ast: parseSource(rel, source) };
      })
      .filter(({ rel }) => rel !== CLAIM_WITNESS && rel !== CLAIM_BASIS);
    const missing: string[] = [];
    const stray: string[] = [];
    const inertObservingCallbacks: string[] = [];
    const seen = new Set<string>();

    for (const { rel, ast } of srcFiles) {
      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) {
          const label = stringLiteralValue(node.arguments[0]);
          if (
            label !== undefined &&
            STRUCTURAL_HONESTY_CLAIM_IDS.includes(label as never)
          ) {
            const helper = expectedHelper(label);
            if (isHelperCall(node, helper)) {
              seen.add(`${helper}:${label}`);
              if (
                helper === "observing" &&
                !observingCallbackCanObserve(node.arguments[1])
              ) {
                inertObservingCallbacks.push(
                  `${rel}:${lineOf(ast, node)} ${label} callback has no real operation call`,
                );
              }
            }
          }
        }
        const literal = stringLiteralValue(node);
        if (
          literal !== undefined &&
          STRUCTURAL_HONESTY_CLAIM_IDS.includes(literal as never)
        ) {
          const parent = node.parent;
          const witnessed =
            parent !== undefined &&
            allowedLiteralHelpers(literal).some((helper) => isHelperCall(parent, helper)) &&
            parent.arguments[0] === node;
          if (!witnessed) {
            stray.push(`${rel}:${lineOf(ast, node)} stray ${JSON.stringify(literal)}`);
          }
        }
        ts.forEachChild(node, visit);
      };
      visit(ast);
    }

    for (const id of STRUCTURAL_HONESTY_CLAIM_IDS) {
      const helper = expectedHelper(id);
      if (!seen.has(`${helper}:${id}`)) {
        missing.push(`${id} via ${helper}`);
      }
    }

    expect(missing).toEqual([]);
    expect(stray).toEqual([]);
    expect(inertObservingCallbacks).toEqual([]);
  });

  it("blocks raw auto-provision and castle-wall definitive outcome claims", () => {
    const orchestrate = readSource("server/src/castle-wall/provision/orchestrate.ts");
    const exclusiveArm = readSource("server/src/castle-wall/provision/exclusive-arm.ts");

    expect(orchestrate).toMatch(/observing\(\s*"provision-orchestrate\.armed"/);
    expect(orchestrate).toContain(`observing("provision-orchestrate.disarmed"`);
    expect(orchestrate).not.toMatch(/disarmObservedOff\s*:\s*(?:true|disarmObservedOff\s*\?\s*true)/);
    expect(orchestrate).not.toContain(`return { kind: "armed", uid }`);

    expect(exclusiveArm).toMatch(
      /observing\(\s*"provision-exclusive-arm\.exclusive-armed"/,
    );
    expect(exclusiveArm).toMatch(
      /observing\(\s*"provision-exclusive-arm\.coarse-composition-restored"/,
    );
    expect(exclusiveArm).toMatch(/ops\.audit\(\.\.\.auditClaim\(\s*EXCLUSIVE_EGRESS_ARMED_AUDIT_OP/);
    expect(exclusiveArm).toMatch(/ops\.audit\(\.\.\.auditClaim\(\s*EXCLUSIVE_EGRESS_DEGRADED_AUDIT_OP/);
    expect(exclusiveArm).toMatch(/ops\.audit\(\.\.\.auditClaim\(\s*EGRESS_GATE_REPAIR_AUDIT_OP/);
    expect(exclusiveArm).toMatch(/ops\.audit\(\.\.\.auditClaim\(\s*EXCLUSIVE_EGRESS_BOOT_RELEASE_AUDIT_OP/);
    expect(exclusiveArm).not.toMatch(/ops\.audit\(\s*EGRESS_GATE_REPAIR_AUDIT_OP/);
    expect(exclusiveArm).not.toMatch(/ops\.audit\(\s*"exclusive_egress_boot_release"/);
    expect(exclusiveArm).not.toMatch(/coarseCompositionRestored\s*=\s*true/);
    expect(exclusiveArm).not.toMatch(/coarseCompositionRestored\s*:\s*true/);
  });

  it("requires a verified-empty witness for scoped definitive-none render paths", () => {
    const observe = readSource("server/src/cli/castle-wall-observe.ts");
    const inventory = readSource("server/src/evidence-pack/inventory.ts");

    const noCandidatesIndex = observe.indexOf(`"No candidates. Turn on observe mode`);
    const noCandidatesGateIndex = observe.lastIndexOf("claimFromVerifiedEmpty(", noCandidatesIndex);
    expect(noCandidatesIndex).toBeGreaterThanOrEqual(0);
    expect(noCandidatesGateIndex).toBeGreaterThanOrEqual(0);
    expect(noCandidatesIndex - noCandidatesGateIndex).toBeLessThan(200);
    expect(observe).toContain("Pending candidates: ${formatPendingCandidateCount(census)}");

    expect(inventory).toContain(`verifiedEmptyFrom("evidence-pack.inventory.empty-verified"`);
    expect(inventory).toContain("claimFromVerifiedEmpty(witness, emptyVerified())");
    expect(inventory).not.toMatch(/return\s+emptyVerified\(\);/);
    expect(inventory).not.toMatch(/:\s*emptyVerified\(\)/);
  });
});
