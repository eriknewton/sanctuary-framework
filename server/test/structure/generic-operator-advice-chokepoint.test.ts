import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import {
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE,
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND,
  EGRESS_GATE_STAND_DOWN_EFFECT,
  EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_ADVICE,
  EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_COMMAND,
  GENERIC_UID_CONFINEMENT_REMEDY,
} from "../../src/egress-gate/operator-advice.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");
const GENERIC_REMEDY_OWNER = "server/src/egress-gate/operator-advice.ts";
const OPERATOR_ADVICE_OWNER = "server/src/egress-gate/operator-advice.ts";

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

const EGRESS_GATE_ADVICE_SURFACES = [
  {
    file: "server/src/castle-wall/provision/exclusive-arm.ts",
    functionName: "degradeLoud",
    requiredConstants: [
      "EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_COMMAND",
      "EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE",
    ],
  },
  {
    file: "server/src/egress-gate/protection-claim.ts",
    functionName: "protectionStateAdvice",
    requiredConstants: [
      "EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND",
      "EGRESS_GATE_STAND_DOWN_EFFECT",
    ],
  },
] as const;

const EGRESS_GATE_RECOVERY_COMMANDS = [
  {
    name: "repair",
    bareCommand: "sudo sanctuary protect --repair-egress-gate",
    command: EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND,
    advice: EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE,
  },
  {
    name: "unprotect",
    bareCommand: "sudo sanctuary protect --unprotect-egress-gate",
    command: EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_COMMAND,
    advice: EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_ADVICE,
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
    // FIX F-REVOKE (2026-07-26): the rollback note names the ONE command that
    // republishes the agent's grants after a restore could not put them back.
    file: "server/src/castle-wall/provision/orchestrate.ts",
    scope: "restoreEgressBestEffort",
    snippet: "Recover with: sudo sanctuary protect --hermes (re-provisions and republishes the agent's grants), ",
    exact: true,
    expectedCount: 1,
    reason: "the provisioning orchestrator is reached from the Hermes-gated auto-provision path",
  },
  {
    // FIX F2 (2026-07-28): shutdown-deadline residual-state reporting names
    // the Hermes provisioning command because this orchestrator entrypoint is
    // currently invoked only from the Hermes-gated auto-provision path.
    file: "server/src/castle-wall/provision/orchestrate.ts",
    scope: "<top-level>",
    snippet: "sudo sanctuary protect --hermes",
    exact: true,
    expectedCount: 1,
    reason: "the provisioning orchestrator is reached from the Hermes-gated auto-provision path",
  },
  {
    // FIX F-PIPX (2026-07-27): the Hermes runtime resolver accepts either
    // the legacy re-homed tree or a measured pipx install, so the remaining
    // command literal is still Hermes-scoped by construction.
    file: "server/src/castle-wall/provision/harness-argv.ts",
    scope: "resolveHermesGatewayArgv",
    snippet: "'sudo sanctuary protect --hermes'.",
    exact: true,
    expectedCount: 1,
    reason: "harness-argv resolves ONLY the Hermes gateway; its refusals are Hermes-scoped by construction",
  },
  {
    // `sanctuary doctor`'s Hermes config-parser check. It only runs on a host
    // that HAS a Hermes config, and it reports on the one surface a missing
    // PyYAML blocks -- the Hermes wrap path -- so naming that exact command is
    // the whole value of the check, not leaked agent-specific advice.
    file: "server/src/cli/doctor.ts",
    scope: "checkHermesConfigParser",
    snippet: "would refuse to edit config.yaml",
    expectedCount: 1,
    reason: "the check is gated on a Hermes config existing and predicts the Hermes wrap path only",
  },
  {
    // FIX F-COARSE-AFTER-EXCLUSIVE (2026-07-26): when the coarse restore FAILS
    // the fortress is left in exclusive routing composition, in which the plain
    // Hermes arm is REFUSED -- so the degrade message must name that command as
    // the one that will not work, and name the verb that clears it.
    file: "server/src/castle-wall/provision/exclusive-arm.ts",
    scope: "degradeLoud",
    snippet: "will be REFUSED until it is",
    expectedCount: 2,
    reason: "the exclusive-egress arming stage is only reached from the Hermes-gated auto-provision path",
  },
  {
    // FIX F-COARSE-AFTER-EXCLUSIVE (2026-07-26): the repair verb's sentence
    // about what the fortress's routing composition was left in.
    file: "server/src/wrap/auto-provision.ts",
    scope: "describeRepairCoarseComposition",
    snippet: "path works again.",
    expectedCount: 2,
    reason: "the repair verb is Hermes-only (`--repair-egress-gate` provisions the Hermes agent account)",
  },
  {
    file: "server/src/wrap/auto-provision.ts",
    scope: "describeRepairCoarseComposition",
    snippet: "will be REFUSED by the composition invariant",
    expectedCount: 1,
    reason: "the repair verb is Hermes-only (`--repair-egress-gate` provisions the Hermes agent account)",
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
    snippet: "Otherwise provision first: sudo sanctuary protect --hermes --exclusive-egress",
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
    snippet: "Re-run 'sanctuary protect --hermes' when you are ready to arm again.",
    exact: true,
    expectedCount: 1,
    reason: "auto-provision outcome text is inside the Hermes protect surface",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "handleProcessShutdownSignal",
    snippet: "Some rollback work may still be incomplete. Re-run 'sudo sanctuary protect --hermes' before assuming recovery.",
    exact: true,
    expectedCount: 1,
    reason: "second-signal fallback guidance is inside protect auto-provisioning shutdown cleanup",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "renderAutoProvisionOutcome",
    snippet: "). Re-run 'sudo sanctuary protect --hermes' or inspect ",
    exact: true,
    expectedCount: 1,
    reason: "guarded auto-provision render fallback is inside the Hermes protect surface",
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
    // FIX (N1-3, 2026-07-26; corrected 2026-07-27): --exclusive-egress /
    // --provision-agent-account without a provisionable agent selector
    // silently armed nothing; the refusal names --hermes because it is the
    // ONLY provisionable agent today, not as leaked agent-specific advice.
    // The 2026-07-27 fix keys the refusal on the RESOLVED platform rather
    // than the CLI hint (so auto-detected/`--wrap`-resolved Hermes hosts
    // aren't wrongly refused), which reworded this literal.
    //
    // FIX (N1-3 dry-run + diagnostics-swallow, harden-loop): the same
    // refusal now ALSO fires (a) before the fresh-config bootstrap's own
    // dry-run early return, so `--dry-run` cannot silently omit it, and
    // (b) in the genuinely-unresolvable-config case, where it used to
    // swallow the "Configuration Not Found" handler's diagnostics -- three
    // occurrences of the same literal across the one provisionable-agent
    // gate in `runWrap`, not three independent refusals. FIX (harden-loop,
    // side-effect-before-refusal): the dry-run-branch occurrence and a
    // twin check placed just before the fresh-config bootstrap's write are
    // now the SAME call, factored into `refuseUnsupportedExclusiveArmForHint`
    // (own scope below) so the write path can't apply a refusal the dry-run
    // path doesn't share (or vice versa) -- leaving 2 remaining inline
    // occurrences directly in `runWrap` (the resolved-config cases).
    file: "server/src/wrap/cli.ts",
    scope: "runWrap",
    snippet: "--hermes against a Hermes config. Without it, wrap would proceed as a ",
    exact: true,
    expectedCount: 2,
    reason: "the refusal fires only for --exclusive-egress / --provision-agent-account without a provisionable selector; Hermes is the only one today -- checked post-bootstrap (resolved config) and in the no-selector-tried config-not-found case; the pre-bootstrap (dry-run + pre-write) check lives in refuseUnsupportedExclusiveArmForHint below",
  },
  {
    // FIX (harden-loop, side-effect-before-refusal): shared helper called
    // from BOTH the dry-run early-return and immediately before the
    // fresh-config bootstrap's real write, so a refused
    // --exclusive-egress / --provision-agent-account never leaves a stub
    // config file on disk (or a "Bootstrapped a fresh config at ..." print)
    // the operator never asked for.
    file: "server/src/wrap/cli.ts",
    scope: "refuseUnsupportedExclusiveArmForHint",
    snippet: "--hermes against a Hermes config. Without it, wrap would proceed as a ",
    exact: true,
    expectedCount: 1,
    reason: "the refusal fires only for --exclusive-egress / --provision-agent-account without a provisionable selector; Hermes is the only one today -- this is the single pre-bootstrap check shared by the dry-run and real-write paths",
  },
  {
    file: "server/src/wrap/cli.ts",
    scope: "<top-level>",
    snippet: "--hermes",
    expectedCount: 3,
    reason: "wrap option metadata declares the real Hermes flag; the shutdown deadline default status is also Hermes-scoped inside protect auto-provisioning",
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

function egressGateRecoveryCommandCopy(text: string): boolean {
  return EGRESS_GATE_RECOVERY_COMMANDS.some((row) => text.includes(row.bareCommand));
}

function quotedGlossBearingAdvice(sourceText: string): boolean {
  return (
    sourceText.includes("'${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE}'") ||
    sourceText.includes("'${EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_ADVICE}'")
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

  it("keeps egress-gate stand-down advice on the shared chokepoint", () => {
    for (const row of EGRESS_GATE_RECOVERY_COMMANDS) {
      expect(
        row.command,
        `${row.name} command must include the explicit stand-down acknowledgement`,
      ).toContain("--stand-down-agent");
      expect(row.advice, `${row.name} advice must state the command effect outside the command`).toBe(
        `${row.command} (${EGRESS_GATE_STAND_DOWN_EFFECT})`,
      );
    }

    for (const surface of EGRESS_GATE_ADVICE_SURFACES) {
      const sourceText = readSource(surface.file);
      const range = findFunctionRange(surface.file, sourceText, surface.functionName);
      const body = sourceText.slice(range.start, range.end);
      for (const requiredConstant of surface.requiredConstants) {
        expect(
          body,
          `${surface.file}:${surface.functionName} must consume ${requiredConstant}`,
        ).toContain(requiredConstant);
      }
    }
  });

  it("keeps hardcoded egress-gate recovery commands out of emitted source", () => {
    const offenders: LiteralHit[] = [];
    const quotedAdviceOffenders: string[] = [];
    for (const filePath of tsFiles(SERVER_SRC)) {
      const file = relative(REPO_ROOT, filePath);
      if (file === OPERATOR_ADVICE_OWNER) continue;
      const sourceText = readFileSync(filePath, "utf8");
      offenders.push(...scanCodeLiterals(file, sourceText, egressGateRecoveryCommandCopy));
      if (quotedGlossBearingAdvice(sourceText)) {
        quotedAdviceOffenders.push(file);
      }
    }
    expect(
      offenders.map((hit) => `${hit.file}:${hit.line} ${JSON.stringify(hit.text)}`),
      "egress-gate recovery commands must be imported from operator-advice.ts, not recopied",
    ).toEqual([]);
    expect(
      quotedAdviceOffenders,
      "gloss-bearing _ADVICE constants must not sit inside quoted command spans; quote the _COMMAND constant only",
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
