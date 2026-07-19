/**
 * THE STRUCTURAL GUARD for the claim register (fix-round 3, 2026-07-19).
 *
 * `claim-basis.ts` explains why this exists: this subsystem produced the same
 * "success derived from control flow, not from an observation" defect four
 * times across three gate rounds, at four different altitudes. Fixing the
 * named site each round is what produced round four. This test makes a NEW
 * unclassified claim visible without a reviewer having to notice it.
 *
 * WHAT IS A COMPILE ERROR vs A FAILING TEST -- stated honestly, because the
 * difference matters and it would be easy to overclaim here:
 *
 *   - COMPILE ERROR: `CLAIM_SITES` is a total `Record<ClaimSiteId, ...>`. Add
 *     an id to the union without a row and `tsc` refuses. (Same shape as
 *     `ARTIFACT_SCOPES` in evidence-pack.)
 *   - FAILING TEST (this file): a claim-shaped literal appearing in either
 *     directory without a matching registry update. This is a ratchet on the
 *     literal COUNT per file, so it catches additions, not just new files.
 *   - NEITHER: a claim in a shape the detector cannot see -- most importantly
 *     a `Promise<void>` whose contract is "this resolving means state X holds",
 *     which is the exact shape of the round-4 blocker. Those rows carry
 *     `detectorBlind: true` and are maintained by review. The guard reduces the
 *     surface a reviewer must hold; it does not eliminate it.
 */

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";

import ts from "typescript";

import {
  CLAIM_LITERAL_COUNTS,
  CLAIM_SITES,
  RUN_STATE_PROSE_EXEMPT,
  RUN_STATE_PROSE_PATTERNS,
  RUN_STATE_PROSE_SCANNED_DIRS,
  RUN_STATE_PROSE_SCANNED_FILES,
  RUN_STATE_PROSE_SOLE_OWNER,
  normalizeRunStateProse,
  claimLiteralRegex,
  type ClaimSiteDeclaration,
  type ClaimSiteId,
} from "../../src/egress-gate/claim-basis.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function readSource(repoRelative: string): string {
  return readFileSync(join(REPO_ROOT, repoRelative), "utf8");
}

function countClaimLiterals(source: string): number {
  const re = claimLiteralRegex();
  let n = 0;
  for (const line of source.split("\n")) {
    const matched = line.match(re);
    if (matched !== null) n += matched.length;
  }
  return n;
}

/**
 * THE RUN-STATE PROSE SCANNER (extracted, fix-round 5). One implementation
 * driven by both the real file sweep and the synthetic-source test below --
 * round 4's guard was never exercised against a sentence it should catch, so
 * nobody noticed it caught nothing.
 *
 * Returns one `file:line` offence per (literal, pattern) pair.
 */
function scanRunStateProse(fileName: string, sourceText: string): string[] {
  const patterns = RUN_STATE_PROSE_PATTERNS.map((phrase) => ({
    phrase,
    needle: normalizeRunStateProse(phrase),
  }));
  const source = ts.createSourceFile(fileName, sourceText, ts.ScriptTarget.ESNext, true);
  const isProseLiteral = (node: ts.Node): boolean =>
    ts.isStringLiteral(node) ||
    ts.isNoSubstitutionTemplateLiteral(node) ||
    ts.isTemplateHead(node) ||
    ts.isTemplateMiddle(node) ||
    ts.isTemplateTail(node);
  /** The rendered text of a `"a" + "b" + ...` chain, or undefined if any operand is not a literal. */
  const flattenConcat = (node: ts.Node): string | undefined => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
    if (ts.isParenthesizedExpression(node)) return flattenConcat(node.expression);
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = flattenConcat(node.left);
      const right = flattenConcat(node.right);
      return left !== undefined && right !== undefined ? left + right : undefined;
    }
    return undefined;
  };

  const offenders: string[] = [];
  const seen = new Set<string>();
  const check = (text: string, node: ts.Node): void => {
    const normalized = normalizeRunStateProse(text);
    for (const { phrase, needle } of patterns) {
      if (!normalized.includes(needle)) continue;
      const { line } = source.getLineAndCharacterOfPosition(node.getStart(source));
      const offence = `${fileName}:${line + 1} contains run-state prose ${JSON.stringify(phrase)}`;
      if (seen.has(offence)) continue;
      seen.add(offence);
      offenders.push(offence);
    }
  };
  const visit = (node: ts.Node): void => {
    if (isProseLiteral(node)) check(node.text, node);
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const flattened = flattenConcat(node);
      if (flattened !== undefined) check(flattened, node);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return offenders;
}

const entries = Object.entries(CLAIM_SITES) as Array<[ClaimSiteId, ClaimSiteDeclaration]>;

describe("claim register: every claim is observed, weakened, or documented", () => {
  it("declares a non-empty claim and a real source symbol for every site", () => {
    const missing: string[] = [];
    for (const [id, site] of entries) {
      expect(site.claim.length, `${id} has an empty claim`).toBeGreaterThan(0);
      const source = readSource(site.file);
      if (!source.includes(site.symbol)) missing.push(`${id} -> ${site.file}#${site.symbol}`);
    }
    // A renamed or deleted symbol rots the register silently otherwise.
    expect(missing, "registry rows naming symbols that no longer exist").toEqual([]);
  });

  it("requires `unobserved` on every documented-bound and weakened row, and forbids it on observed rows", () => {
    const offenders: string[] = [];
    for (const [id, site] of entries) {
      const hasBound = site.unobserved !== undefined && site.unobserved.trim().length > 0;
      if (site.basis === "observed" && hasBound) {
        offenders.push(`${id}: observed rows must not carry an unobserved note`);
      }
      if (site.basis !== "observed" && !hasBound) {
        // THE RULE: silence is not an option. A control-flow-derived claim
        // that does not name what it failed to observe is a defect.
        offenders.push(`${id}: ${site.basis} rows must name what is NOT observed`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("keeps the round-3 fixes classified as observed (a regression here means a claim went back to intent)", () => {
    // These four are the sites the three gate rounds actually broke on. If a
    // future change downgrades one, this test names it rather than leaving it
    // to a fifth review round.
    const mustBeObserved: ClaimSiteId[] = [
      "release-barrier.reassert-parked-stopped",
      "release-barrier.revert-harness-restarted",
      "release-barrier.revert-plist-restored",
      "harness-daemon.set-job-disabled",
      "harness-daemon.uninstall-stopped",
      "harness-daemon.install-reload",
      "release-barrier.park-cleanup-job-disabled",
      "arming-wiring.barrier-remove-hold",
    ];
    for (const id of mustBeObserved) {
      expect(CLAIM_SITES[id].basis, `${id} must stay observed`).toBe("observed");
    }
  });
});

describe("claim register: the literal ratchet", () => {
  it("matches the recorded per-file claim-literal counts", () => {
    const drift: string[] = [];
    for (const [file, expected] of Object.entries(CLAIM_LITERAL_COUNTS)) {
      const actual = countClaimLiterals(readSource(file));
      if (actual !== expected) {
        drift.push(`${file}: recorded ${expected}, found ${actual}`);
      }
    }
    // If this fails you have added (or removed) a claim-shaped literal in the
    // exclusive-egress subsystem. That is not a reason to bump the number: go
    // to `src/egress-gate/claim-basis.ts`, decide whether the new claim is
    // OBSERVED, WEAKENED, or a DOCUMENTED BOUND, add its row, and update the
    // count in the same commit. The number is the forcing function, not the
    // requirement.
    expect(drift, "claim-literal drift -- classify the new claim in claim-basis.ts").toEqual([]);
  });

  it("keeps run-state prose in exactly ONE file", () => {
    // THE RENDER-LAYER GUARD. Round 4's HIGH was a SENTENCE, and no count
    // ratchet could have caught it. This is an ownership rule instead: the
    // phrases that assert whether the agent process is alive may exist only in
    // the chokepoint that can produce them from a settled observation. Every
    // other surface prints `ParkedClaim.sentence`.
    //
    // PARSER-based on purpose: it walks the TypeScript AST's string and
    // template literals, so doc comments stay free to discuss parking in plain
    // English. A line scanner cannot tell prose from code and would either
    // gag the comments or miss a multi-line template.
    const files = [
      ...RUN_STATE_PROSE_SCANNED_FILES,
      ...RUN_STATE_PROSE_SCANNED_DIRS.flatMap((dir) =>
        readdirSync(join(REPO_ROOT, dir))
          .filter((f) => f.endsWith(".ts"))
          .map((f) => `${dir}/${f}`),
      ),
    ].filter((f) => f !== RUN_STATE_PROSE_SOLE_OWNER && RUN_STATE_PROSE_EXEMPT[f] === undefined);

    const offenders = files.flatMap((file) => scanRunStateProse(file, readSource(file)));
    // If this fails you have written a sentence about whether the agent is
    // running, somewhere other than `parked-claim.ts`. That is the round-4
    // defect. Do not reword around the pattern list: obtain a `ParkedClaim`
    // from `assessHarnessParked` and print its `sentence`.
    expect(offenders, "run-state prose outside the parked-claim chokepoint").toEqual([]);
  });

  it("R5: the guard catches the SHOUTED, WRAPPED and SPLIT forms it used to miss", () => {
    // FIX-ROUND 5, the gate's Finding 2. Round 4 wrote the pattern list from
    // the sentences it had just fixed ("is stopped") and compared with a raw
    // `includes`, while every surviving assertion in the tree was written
    // `is STOPPED`. Three real evasions sat in the tree with the build green,
    // one of them the round-5 HIGH -- findable by this round's own tool, one
    // `toLowerCase()` away.
    //
    // These are the ACTUAL sentences that evaded it, verbatim, plus the split
    // form the Codex lens demonstrated. Asserted on the scanner's OUTPUT.
    const evasions: Array<[string, string]> = [
      [
        "the round-5 HIGH, shouted",
        'const s = `The agent harness (${label}) is STOPPED. Re-run to bring it back up.`;',
      ],
      [
        "release-barrier.ts:1154, shouted",
        'const s = "the agent harness was running before this run and is STOPPED now";',
      ],
      ["wrap/cli.ts:1281, lower case", 'const s = "the agent is running confined, but";'],
      [
        "wrapped across lines inside one template",
        "const s = `the agent\n  is not\n  running right now`;",
      ],
      ["split across a concatenation", 'const s = "The agent is " + "PARKED" + " today";'],
    ];
    for (const [name, source] of evasions) {
      expect(scanRunStateProse("synthetic.ts", source), `${name} must be caught`).not.toEqual([]);
    }
    // ...and the guard still leaves doc comments alone, which is the whole
    // reason it is parser-based rather than a line scanner.
    expect(
      scanRunStateProse(
        "synthetic.ts",
        "/** Returns whether the agent is PARKED (not running) on this host. */\nexport const x = 1;",
      ),
      "doc comments must stay free to discuss parking in plain English",
    ).toEqual([]);
  });

  it("does not silently lose a tracked file", () => {
    for (const file of Object.keys(CLAIM_LITERAL_COUNTS)) {
      expect(() => readSource(file), `${file} is tracked but unreadable`).not.toThrow();
    }
  });

  it("classifies BOTH branches of every boolean-backed row", () => {
    // Fix-round 4, Part B blind spot 1. The register was one row per FLAG, and
    // a boolean carries two claims: `harness-started-coarse` was correctly
    // `observed` for its true branch while its FALSE branch -- the branch that
    // was rendered as "The agent is PARKED (not running)" over a live pid --
    // had no row at all. `branches: "boolean"` makes `negativeBranch` a
    // COMPILE-time requirement; this test enforces the same content rules on
    // the negative branch that the positive one has always had.
    const offenders: string[] = [];
    for (const [id, site] of entries) {
      if (site.branches !== "boolean") continue;
      const neg = site.negativeBranch;
      if (neg.claim.trim().length === 0) {
        offenders.push(`${id}: negative branch has an empty claim`);
      }
      const hasBound = neg.unobserved !== undefined && neg.unobserved.trim().length > 0;
      if (neg.basis === "observed" && hasBound) {
        offenders.push(`${id}: an observed negative branch must not carry an unobserved note`);
      }
      if (neg.basis !== "observed" && !hasBound) {
        offenders.push(`${id}: a ${neg.basis} negative branch must name what is NOT observed`);
      }
    }
    expect(offenders).toEqual([]);
    // The shape is worthless if nobody uses it.
    expect(entries.filter(([, s]) => s.branches === "boolean").length).toBeGreaterThan(20);
  });

  it("reaches the RENDER layer, not only where claims are computed", () => {
    // Fix-round 4, Part B blind spot 2: the register had 95 rows and zero on
    // the layer the operator actually reads, which is where the round-4 HIGH
    // printed.
    const render = entries.filter(([, site]) => site.layer === "render");
    expect(render.length).toBeGreaterThan(0);
    expect(
      render.some(([, site]) => site.file === "server/src/wrap/cli.ts"),
      "wrap/cli.ts is where the false sentence printed; it must be in the register",
    ).toBe(true);
  });

  it("states its own bound: detector-blind rows exist and are declared, not hidden", () => {
    const blind = entries.filter(([, site]) => site.detectorBlind === true);
    // The guard's honesty check. If this ever reaches zero, someone has
    // quietly deleted the acknowledgement that `Promise<void>` claims -- the
    // shape of the round-4 blocker -- are not machine-detected.
    expect(blind.length).toBeGreaterThan(0);
  });
});
