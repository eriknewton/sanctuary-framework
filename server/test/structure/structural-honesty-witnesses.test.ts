import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
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

function observingCallbackCanObserve(callback: ts.Expression | undefined): boolean {
  if (
    callback === undefined ||
    (!ts.isArrowFunction(callback) && !ts.isFunctionExpression(callback))
  ) {
    return false;
  }
  let canObserve = false;
  const visit = (node: ts.Node): void => {
    if (ts.isAwaitExpression(node) || ts.isCallExpression(node)) {
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
        offenders.push(rel);
      }
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
                  `${rel}:${lineOf(ast, node)} ${label} callback has no await or call expression`,
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
