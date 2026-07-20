import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { GENERIC_UID_CONFINEMENT_REMEDY } from "../../src/egress-gate/operator-advice.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");
const GENERIC_REMEDY_OWNER = "server/src/egress-gate/operator-advice.ts";

const GENERIC_ADVICE_SURFACES = [
  {
    file: "server/src/egress-gate/protection-claim.ts",
    functionName: "protectionStateAdvice",
  },
  {
    file: "server/src/cli/castle-wall.ts",
    functionName: "runArmDisarm",
  },
] as const;

interface HermesLiteralClassification {
  readonly file: string;
  readonly scope: string;
  readonly snippet: string;
  readonly exact?: boolean;
  readonly expectedCount: number;
  readonly reason: string;
}

const HERMES_LITERAL_CLASSIFICATIONS: readonly HermesLiteralClassification[] = [
  {
    file: "server/src/castle-wall/provision/orchestrate.ts",
    scope: "harnessRestoreNote",
    snippet: "Nothing was running before this run began",
    expectedCount: 1,
    reason: "the provisioning orchestrator is reached from the Hermes-gated auto-provision path",
  },
  {
    file: "server/src/castle-wall/provision/orchestrate.ts",
    scope: "harnessRestoreNote",
    snippet: "before re-running 'sudo sanctuary protect --hermes'.",
    exact: true,
    expectedCount: 1,
    reason: "the provisioning orchestrator is reached from the Hermes-gated auto-provision path",
  },
  {
    file: "server/src/cli.ts",
    scope: "printWrapHelpEarly",
    snippet: "sanctuary protect --hermes         Protect Hermes Agent",
    expectedCount: 1,
    reason: "top-level protect help names the real Hermes command; it is not generic recovery advice",
  },
  {
    file: "server/src/egress-gate/parked-claim.ts",
    scope: "runStateAdvice",
    snippet: "Re-run 'sudo sanctuary protect --hermes' to bring it back up -- but NOT",
    expectedCount: 3,
    reason: "run-state recovery advice is intentionally scoped to protect --hermes recovery paths",
  },
  {
    file: "server/src/egress-gate/parked-claim.ts",
    scope: "runStateAdvice",
    snippet: "Re-run 'sudo sanctuary protect --hermes' to bring it back up under the previous",
    expectedCount: 1,
    reason: "run-state recovery advice is intentionally scoped to protect --hermes recovery paths",
  },
  {
    file: "server/src/egress-gate/parked-claim.ts",
    scope: "runStateAdvice",
    snippet: "Do NOT re-run 'sudo sanctuary protect --hermes' expecting it to restart the agent",
    expectedCount: 1,
    reason: "run-state recovery advice is intentionally scoped to protect --hermes recovery paths",
  },
  {
    file: "server/src/egress-gate/parked-claim.ts",
    scope: "runStateAdvice",
    snippet: "): 'sudo sanctuary protect --hermes' ",
    expectedCount: 1,
    reason: "run-state recovery advice is intentionally scoped to protect --hermes recovery paths",
  },
  {
    file: "server/src/templates/cli.ts",
    scope: "cmdInit",
    snippet: "--openclaw, --hermes, --cursor",
    expectedCount: 1,
    reason: "template help lists --hermes as one possible wrap flag, not as recovery advice",
  },
  {
    file: "server/src/wrap/auto-provision.ts",
    scope: "runAutoProvisionForWrap",
    snippet: "Provisioning a dedicated agent account requires root",
    expectedCount: 1,
    reason: "auto-provision is called only after wrap/cli.ts gates platform === hermes",
  },
  {
    file: "server/src/wrap/auto-provision.ts",
    scope: "runAutoProvisionForWrap",
    snippet: "Could not determine the operator account under sudo",
    expectedCount: 1,
    reason: "auto-provision is called only after wrap/cli.ts gates platform === hermes",
  },
  {
    file: "server/src/wrap/auto-provision.ts",
    scope: "runAutoProvisionForWrap",
    snippet: "Run via 'sudo sanctuary protect --hermes' from an interactive operator shell, not a raw root shell.",
    exact: true,
    expectedCount: 1,
    reason: "auto-provision is called only after wrap/cli.ts gates platform === hermes",
  },
  {
    file: "server/src/wrap/auto-provision.ts",
    scope: "runEgressGateRepairForCli",
    snippet: "Provision first: sudo sanctuary protect --hermes --exclusive-egress",
    expectedCount: 1,
    reason: "egress-gate repair still delegates to the Hermes provisioning command",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "renderAutoProvisionOutcomeLines",
    snippet: "Re-run 'sanctuary protect --hermes' once the connectivity re-check passes",
    expectedCount: 1,
    reason: "auto-provision outcome text is inside the Hermes protect surface",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "renderAutoProvisionOutcomeLines",
    snippet: "then investigate before re-running 'sanctuary protect --hermes'",
    expectedCount: 1,
    reason: "auto-provision outcome text is inside the Hermes protect surface",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "renderAutoProvisionOutcomeLines",
    snippet: "Re-run 'sanctuary protect --hermes' once the per-endpoint failures",
    expectedCount: 1,
    reason: "auto-provision outcome text is inside the Hermes protect surface",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "abortedProvisionLines",
    snippet: "Reconcile the file(s) above, then re-run 'sanctuary protect --hermes'",
    expectedCount: 1,
    reason: "aborted auto-provision text is inside the Hermes protect surface",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "abortedProvisionLines",
    snippet: "Re-run 'sanctuary protect --hermes' once the cause above is resolved",
    expectedCount: 1,
    reason: "aborted auto-provision text is inside the Hermes protect surface",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "abortedProvisionLines",
    snippet: "Re-homed paths were restored to your account. Re-run 'sanctuary protect --hermes'",
    expectedCount: 1,
    reason: "aborted auto-provision text is inside the Hermes protect surface",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "runWrap",
    snippet: "Use --openclaw, --hermes, --claude-code",
    expectedCount: 1,
    reason: "wrap parser guidance lists supported agent flags",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "<top-level>",
    snippet: "--hermes",
    expectedCount: 2,
    reason: "wrap option metadata declares the real Hermes flag",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "parseWrapArgs",
    snippet: "--hermes",
    expectedCount: 1,
    reason: "wrap argument parsing handles the real Hermes flag",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "printWrapHelp",
    snippet: "sanctuary wrap --hermes            Wrap Hermes Agent",
    expectedCount: 1,
    reason: "wrap help names the real Hermes command; it is not recovery advice",
  },
];

interface LiteralHit {
  readonly file: string;
  readonly line: number;
  readonly scope: string;
  readonly text: string;
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

function readSource(file: string): string {
  return readFileSync(join(REPO_ROOT, file), "utf8");
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

function literalText(node: ts.Node): string | undefined {
  if (
    ts.isStringLiteral(node) ||
    ts.isNoSubstitutionTemplateLiteral(node) ||
    ts.isTemplateHead(node) ||
    ts.isTemplateMiddle(node) ||
    ts.isTemplateTail(node)
  ) {
    return node.text;
  }
  if (
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    return flattenConcat(node);
  }
  return undefined;
}

function scopeNameFor(node: ts.Node): string | undefined {
  if (ts.isFunctionDeclaration(node) && node.name !== undefined) {
    return node.name.text;
  }
  if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) {
    return node.name.text;
  }
  if (ts.isFunctionExpression(node) || ts.isArrowFunction(node)) {
    const parent = node.parent;
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
    if (ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
  }
  return undefined;
}

function scanCodeLiterals(
  file: string,
  sourceText: string,
  predicate: (text: string) => boolean,
  range?: { readonly start: number; readonly end: number },
): LiteralHit[] {
  const source = ts.createSourceFile(file, sourceText, ts.ScriptTarget.ESNext, true);
  const seen = new Set<string>();
  const hits: LiteralHit[] = [];
  const visit = (node: ts.Node, currentScope: string): void => {
    const scope = scopeNameFor(node) ?? currentScope;
    const start = node.getStart(source);
    if (range !== undefined && (start < range.start || start > range.end)) {
      ts.forEachChild(node, (child) => visit(child, scope));
      return;
    }
    const text = literalText(node);
    if (text !== undefined && predicate(text)) {
      const { line } = source.getLineAndCharacterOfPosition(start);
      const key = `${file}:${line + 1}:${scope}:${text}`;
      if (!seen.has(key)) {
        seen.add(key);
        hits.push({ file, line: line + 1, scope, text });
      }
    }
    ts.forEachChild(node, (child) => visit(child, scope));
  };
  visit(source, "<top-level>");
  return hits;
}

function findFunctionRange(
  file: string,
  sourceText: string,
  functionName: string,
): { start: number; end: number } {
  const source = ts.createSourceFile(file, sourceText, ts.ScriptTarget.ESNext, true);
  let found: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node): void => {
    if (
      found === undefined &&
      ts.isFunctionDeclaration(node) &&
      node.name?.text === functionName
    ) {
      found = node;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  if (found === undefined) {
    throw new Error(`${file}: function ${functionName} not found`);
  }
  return { start: found.getStart(source), end: found.end };
}

function hermesSpecific(text: string): boolean {
  return text.includes("--hermes");
}

function genericRemedyCopy(text: string): boolean {
  return (
    text.includes("uid-confined") ||
    text.includes("per-agent enforcement evidence can bind") ||
    text.includes("configure-origin uid --agent-uid=<uid> --ceiling=500")
  );
}

function matchingHermesClassifications(hit: LiteralHit): number[] {
  return HERMES_LITERAL_CLASSIFICATIONS.flatMap((classification, index) =>
    classification.file === hit.file &&
    classification.scope === hit.scope &&
    (classification.exact
      ? hit.text === classification.snippet
      : hit.text.includes(classification.snippet))
      ? [index]
      : [],
  );
}

describe("generic operator advice chokepoint", () => {
  it("keeps the shared uid-confinement remedy agent-agnostic", () => {
    expect(GENERIC_UID_CONFINEMENT_REMEDY).toContain("configure-origin uid");
    expect(GENERIC_UID_CONFINEMENT_REMEDY).toContain("--agent-uid=<uid>");
    expect(GENERIC_UID_CONFINEMENT_REMEDY).toContain("--ceiling=500");
    expect(GENERIC_UID_CONFINEMENT_REMEDY).toContain("reload or re-arm Castle Wall");
    expect(GENERIC_UID_CONFINEMENT_REMEDY).not.toContain("--hermes");
  });

  it("routes known generic advice surfaces through the shared remedy", () => {
    for (const surface of GENERIC_ADVICE_SURFACES) {
      const sourceText = readSource(surface.file);
      const range = findFunctionRange(surface.file, sourceText, surface.functionName);
      const body = sourceText.slice(range.start, range.end);
      expect(
        body,
        `${surface.file}:${surface.functionName} must consume the shared generic remedy`,
      ).toContain("GENERIC_UID_CONFINEMENT_REMEDY");
      expect(
        scanCodeLiterals(surface.file, sourceText, hermesSpecific, range),
        `${surface.file}:${surface.functionName} must not print Hermes-specific flags as generic advice`,
      ).toEqual([]);
    }
  });

  it("keeps hardcoded copies of the generic uid-confinement remedy out of source", () => {
    const offenders: LiteralHit[] = [];
    for (const filePath of tsFiles(SERVER_SRC)) {
      const file = relative(REPO_ROOT, filePath);
      if (file === GENERIC_REMEDY_OWNER) continue;
      offenders.push(
        ...scanCodeLiterals(file, readFileSync(filePath, "utf8"), genericRemedyCopy),
      );
    }
    expect(
      offenders.map((hit) => `${hit.file}:${hit.line} ${JSON.stringify(hit.text)}`),
      "generic uid-confinement advice must be imported from operator-advice.ts, not recopied",
    ).toEqual([]);
  });

  it("classifies every runtime --hermes literal as Hermes-scoped", () => {
    const hits: LiteralHit[] = [];
    for (const filePath of tsFiles(SERVER_SRC)) {
      const file = relative(REPO_ROOT, filePath);
      hits.push(...scanCodeLiterals(file, readFileSync(filePath, "utf8"), hermesSpecific));
    }

    const counts = new Map<number, number>();
    const unclassified: LiteralHit[] = [];
    const ambiguous: Array<{ readonly hit: LiteralHit; readonly matches: number[] }> = [];
    for (const hit of hits) {
      const matches = matchingHermesClassifications(hit);
      if (matches.length === 0) {
        unclassified.push(hit);
      } else if (matches.length > 1) {
        ambiguous.push({ hit, matches });
      } else {
        const [match] = matches;
        counts.set(match, (counts.get(match) ?? 0) + 1);
      }
    }

    expect(
      ambiguous.map(
        ({ hit, matches }) =>
          `${hit.file}:${hit.line}:${hit.scope} ${JSON.stringify(hit.text)} matched ${matches.length} classifications`,
      ),
      "Hermes literal classifications must be specific enough to classify each hit once",
    ).toEqual([]);

    expect(
      unclassified.map(
        (hit) => `${hit.file}:${hit.line}:${hit.scope} ${JSON.stringify(hit.text)}`,
      ),
      "a new --hermes runtime literal needs an explicit Hermes-scoped classification; generic advice must use GENERIC_UID_CONFINEMENT_REMEDY",
    ).toEqual([]);

    const countMismatches = HERMES_LITERAL_CLASSIFICATIONS.flatMap(
      (classification, index) => {
        const actual = counts.get(index) ?? 0;
        return actual === classification.expectedCount
          ? []
          : [
              `${classification.file}:${classification.scope} ${JSON.stringify(
                classification.snippet,
              )} expected ${classification.expectedCount}, saw ${actual} (${classification.reason})`,
            ];
      },
    );
    expect(countMismatches, "Hermes literal classifications must stay live").toEqual([]);
  });
});
