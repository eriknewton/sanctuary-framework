/**
 * DISCLOSURE guard — structural cover for the non-disclosure rule.
 *
 * THE RULE (AGENTS.md MUST-NEVER #9, tightened 2026-08-16): a pull-request
 * description, and any test-file header, may never describe a defect. What
 * either may carry is the capability change plus a bare private-register id.
 *
 * WHY A GUARD AND NOT A CONVENTION. The rule failed three times on one pull
 * request inside a single day. Two of the three were written by an author who
 * was actively trying to comply, and the second of those named no file at all
 * yet still narrowed a reader to one search by pairing a behaviour description
 * with a scope this repository already publishes. Judgment is not reliable on
 * this rule, the surface is public the moment the text is saved, and the host
 * keeps edit history, so an after-the-fact correction is incomplete. The gate
 * has to refuse first.
 *
 * THREE CHECKS HERE.
 *
 *   1. MUST-FAIL corpus. Every entry has to be refused. The corpus is not the
 *      three past instances copied down; it is the SHAPES they belong to, plus
 *      near-misses that no past instance took. A checker that only recognises
 *      what already went wrong has learned nothing.
 *
 *   2. MUST-PASS corpus. It matters exactly as much. A gate that reds an honest
 *      description gets bypassed inside a week and then protects nothing, so
 *      the passing set carries real merged commit subjects, an honest capability
 *      bound, and a body that names a workflow it adds.
 *
 *   3. IN-REPO RATCHET over test-file headers. Committed headers are scanned
 *      and the per-rule hit total may never rise above the committed baseline.
 *
 * WHY THE BASELINE IS A SET OF COUNTS AND NOT A LIST OF FILES. Every other
 * ratchet here (the em-dash baseline, the import-cycle baseline) stores a
 * per-file row, which is the more precise design and is the right one for those
 * rules. It is the wrong one for this rule: a committed, permanent list of
 * which headers trip a non-disclosure check is itself an index that tells a
 * reader where to start. Counts give up per-file precision to avoid publishing
 * that index. The cost is stated in the ratchet's own failure message: a
 * one-for-one swap inside a single rule passes. The compensating control is the
 * pull-request diff, which a reviewer reads.
 *
 * SCOPE. In-tree, the rule names test-file headers, so that is what check 3
 * covers. Pull-request descriptions are not in the tree; they are gated by
 * .github/workflows/disclosure-guard.yml, whose wiring check 4 asserts.
 */

import { describe, it, expect } from "vitest";
import { spawnSync, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// server/test/structure/<file> -> repo root is four levels up (same anchor the
// other structure gates use).
const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const CHECKER = join(REPO_ROOT, "scripts", "check-disclosure.sh");
const BASELINE_PATH = join(
  fileURLToPath(import.meta.url),
  "..",
  "disclosure-baseline.txt",
);
const WORKFLOW_PATH = join(
  REPO_ROOT,
  ".github",
  "workflows",
  "disclosure-guard.yml",
);

/**
 * The private-register id shape the checker masks before any rule runs.
 * Must match the register-id substitution in scripts/check-disclosure.sh: an
 * all-caps hyphenated token carrying at least one digit. The two are pinned to
 * each other because the mask is what makes a compliant body ("... hardening
 * (SYNC-APPEND-01)") pass; if the shapes drift apart the guard starts refusing
 * the exact form the rule requires.
 */
const REGISTER_ID_SHAPE = /^[A-Z0-9]+(-[A-Z0-9]+)+$/;

type Surface = "pr-body" | "test-header";

function runChecker(
  body: string,
  surface: Surface = "pr-body",
): { status: number; stdout: string; stderr: string } {
  const result = spawnSync(CHECKER, ["--surface", surface, "--label", "corpus", "-"], {
    cwd: REPO_ROOT,
    input: body,
    encoding: "utf8",
  });
  return {
    status: result.status ?? -1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

/**
 * MUST FAIL. Each entry is labelled with the shape it stands for, so a future
 * editor can tell which class an entry is defending and does not delete the
 * only witness for one.
 *
 * THE FOUR ENTRIES MARKED `wave analogue` ARE THE REAL CORPUS, ONE STEP REMOVED.
 * They come from the four texts that actually reached a surface during the
 * triggering wave, and the first version of this checker refused only two of
 * them. Each analogue preserves every token the matcher keys on and the exact
 * grammar of the original; only the referents are swapped, so the sentence no
 * longer describes anything real in this repository.
 *
 * That substitution is not squeamishness, it is the rule applying to itself.
 * Committing the originals would publish four defect descriptions permanently,
 * in-tree, which is the thing MUST-NEVER #9 forbids and the thing this file
 * exists to prevent. A guard whose own fixtures violate it would be worthless.
 * The originals were run against the checker at build time and each is refused;
 * they live only in the private register, addressed by bare id.
 *
 * The consequence to be honest about: an analogue proves the SHAPE is caught,
 * not that the original is. Those two claims come apart if a future edit keys a
 * rule on a referent rather than a shape. Do not do that.
 */
const MUST_FAIL: ReadonlyArray<{ shape: string; body: string }> = [
  {
    shape: "anchor with a line number",
    body: "Corrects the tip comparison in server/src/audit/chain.ts:412.",
  },
  {
    shape: "anchor without a line number, with defect adjacency",
    body: "Corrects the regression in server/src/audit/chain.ts.",
  },
  {
    shape: "bare source filename with defect adjacency",
    body: "The bug lands in checkpoint-signer.ts.",
  },
  {
    shape: "a Rust path with defect adjacency (the guard is not TypeScript-only)",
    body: "The vulnerability in castle-wall-daemon/src/enforce.rs lets an attacker bypass the lease.",
  },
  {
    shape: "presence claim on main",
    body: "This defect is live on main today and the fix is queued behind it.",
  },
  {
    shape: "presence claim against a release",
    body: "The flaw remains unpatched in the current release.",
  },
  {
    shape: "presence claim in the adverbial form",
    body: "The verifier is still bypassable, so this change closes it.",
  },
  {
    shape: "reproduction",
    body: "Steps to reproduce: start the server with the default profile and re-send the head.",
  },
  {
    shape: "attacker sentence",
    body: "An attacker can present a stale quorum input and be admitted.",
  },
  {
    shape: "proof-of-concept wording",
    body: "A proof of concept is attached to the private register entry.",
  },
  {
    shape: "severity attached to a defect",
    body: "Closes a HIGH severity vulnerability found during the second pass.",
  },
  {
    shape: "severity in the field form",
    body: "Severity: critical. Fix follows in the next commit.",
  },
  // The hard class. No file is named in any of the four below. Each localizes a
  // defect by pairing its BEHAVIOUR with a scope this repository already
  // publishes, which is the shape that survived a careful hand-scrub and still
  // reached a public surface.
  {
    shape: "class plus subsystem name, no file",
    body: "Tip verification in the audit chain accepts a replayed head.",
  },
  {
    shape: "class plus a different subsystem, no file",
    body: "A counter under the fortress recovery flow can be replayed to roll the tip back.",
  },
  {
    shape: "class plus a directory scope, no subsystem word",
    body: "The optional signer under server/src means the shipped path is never verified.",
  },
  {
    shape: "class plus scope, phrased as an omission",
    body: "The mesh sync loop grants admission without any check on the caller.",
  },
  {
    shape: "runnable command in a body that also names a defect",
    body: [
      "The bug shows up only under the default profile.",
      "",
      "```",
      "$ npx @sanctuary-framework/mcp-server --bind 0.0.0.0",
      "```",
    ].join("\n"),
  },
  {
    shape: "path beside defect language, config extension",
    body: "The regression sits in the policy loaded from principal-policy.yaml.",
  },
  // ---- the four wave analogues ----
  {
    shape: "wave analogue 1: reproduction plus a file-and-line anchor",
    body: [
      "Reproduction: start the listener with the default profile and replay the",
      "frame. The mishandling is in server/src/router.ts:270.",
    ].join("\n"),
  },
  {
    shape: "wave analogue 2: first scrub, still naming a file with defect adjacency",
    body: "The same vulnerability remains in server/src/recovery/escrow.ts, outside this layer.",
  },
  {
    // The second scrub. Named no file, and the first version of this checker
    // passed it. Two rules refuse it now: the source-tree directory (D2) and the
    // residual-existence class beside a scope (D8). Both were added for it.
    shape: "wave analogue 3: residual instance of a class, plus a source-tree directory",
    body: [
      "A further instance of the same silent-degradation randomness class exists",
      "outside the recovery layer. It is tracked in the private register and is out",
      "of scope for this row; the new scan here is bounded to `server/src/recovery`,",
      "and widening it is part of that separate change.",
    ].join("\n"),
  },
  {
    // Named no path and no subsystem at all, only mechanism. Refused by D10,
    // which is the one rule that stands alone without a locator.
    shape: "wave analogue 4: mechanism only, no path and no subsystem",
    body: [
      "Not fully bounded: the governor bounds how many entries this path may write",
      "per window. The shared roster those entries land in is uncapped, and the new",
      "drop paths also call the rejection hook ungoverned into a shared unbounded",
      "roster.",
    ].join("\n"),
  },
  {
    shape: "source path with generic defect adjacency",
    body: "Covers server/src/audit/index.ts, where the regression was introduced.",
  },
];

/**
 * MUST PASS. Real merged commit subjects and the honest shapes the rule
 * explicitly protects. If a change to the checker reds any of these, the
 * checker is wrong, not the corpus.
 */
const MUST_PASS: ReadonlyArray<{ shape: string; body: string }> = [
  {
    shape: "capability change plus bare register ids",
    body: [
      "fix(mesh): v2 quorum-input freshness + sync hardening (C12-REPLAY, SYNC-APPEND-01, QI-SIBLING-01)",
      "",
      "The relying side now bounds the accepted age of a quorum input and clamps",
      "the lifetime it will sign. Register: C12-REPLAY, SYNC-APPEND-01.",
    ].join("\n"),
  },
  {
    shape: "two register ids separated by a single character",
    body: "Closes IC-05-DG/O-02 with a relying-side age bound.",
  },
  {
    shape: "roadmap severity with no defect noun",
    body: [
      "docs(roadmap): capture local audit-chain tamper-evidence hardening as a CRITICAL coming item",
      "",
      "Adds the roadmap row and its registry evidence pointer.",
    ].join("\n"),
  },
  {
    // The honesty obligation inside MUST-NEVER #9. Absence of a capability is
    // required to be stated plainly and must never be softened, so it must
    // never be refused here either.
    shape: "honest capability bound",
    body: [
      "Linux egress enforcement is not implemented. This capability is unproven",
      "on Linux and the matrix row stays capped at partial until a drill is",
      "captured on the platform that matters.",
    ].join("\n"),
  },
  {
    shape: "honest bound, shorter form",
    body: "This capability is unproven on Linux.",
  },
  {
    shape: "a body that names the workflow it adds",
    body: [
      "Adds a checker and a CI job so the rule is enforced mechanically.",
      "",
      "Run it locally:",
      "",
      "```",
      "$ scripts/check-disclosure.sh body.md",
      "```",
    ].join("\n"),
  },
  {
    shape: "capability described in the positive",
    body: [
      "fix(castle-wall): sign the ArmLeaseBody IPC frame and consume updatedAt (O-02 code half)",
      "",
      "The lease payload is signed end to end and the consumer reads updatedAt",
      "from the signed frame.",
    ].join("\n"),
  },
  {
    shape: "subsystem name with no defect class",
    body: "feat(audit): silent-downgrade detection for checkpoint signing (IC-05-DG)",
  },
  {
    shape: "prose using 'critical path' in its ordinary sense",
    body: "Shortens the critical path through the verifier by one hash.",
  },
  {
    shape: "reproducible builds, which are a wanted property",
    body: "The release tarball is now byte-for-byte reproducible across hosts.",
  },
  // ---- the separators D10 and the residual class must not cross ----
  // Each of these sits one word away from a must-fail entry. They are the
  // evidence that closing wave analogues 3 and 4 did not cost the honest half;
  // without them, a later widening of MECHANISM_NEG or the residual family
  // would look free.
  {
    shape: "protection-negation attributive, after a rejection verb",
    body: "Rejects an unsigned checkpoint and refuses an unauthenticated bind.",
  },
  {
    shape: "protection-negation attributive, on the object of a verification",
    body: "Verification now rejects unverified input at the boundary.",
  },
  {
    shape: "the positive form of what D10 refuses",
    body: "Adds a per-origin quota and an eviction rule to the retention map.",
  },
  {
    shape: "a cap stated as a capability",
    body: "The queue is now capped at a fixed number of entries.",
  },
  {
    shape: "an ordinal that is not a residual-instance claim",
    body: "Adds a second guard to the sync path.",
  },
  {
    shape: "bare Markdown heading",
    body: "## Testing",
  },
  {
    shape: "ordinary Markdown table structure",
    body: [
      "| Check | Result |",
      "| --- | --- |",
      "| Typecheck | clean |",
    ].join("\n"),
  },
  {
    shape: "source path without defect adjacency",
    body: "Typecheck is clean for server/src/audit/index.ts.",
  },
  {
    shape: "positive domain separator enforcement",
    body: "Adds a code-controlled domain-separator constant for signed records.",
  },
  {
    shape: "positive malformed-input refusal",
    body: "The parser now refuses malformed inputs before dispatch.",
  },
  // ---- structural boundary tests: paragraph separation prevents matching ----
  {
    shape: "path in one list item, defect in the next (must pass)",
    body: [
      "- Covers server/src/audit/index.ts.",
      "- Fixes an issue with incorrect state transitions.",
    ].join("\n"),
  },
  {
    // Defect/regression prose on the immediately preceding nonblank line, then an
    // indented ordered item containing the path. Passes only because the ordered
    // item is a structural boundary: under blank-line-only assembly both lines
    // would be in the same paragraph and D2 would fire (defect + path).
    shape: "ordered list item with path, regression prose on the immediately preceding nonblank line (must pass)",
    body: [
      "This change addresses the regression in the component.",
      "   1. Covers server/src/audit/index.ts for all cases.",
    ].join("\n"),
  },
  {
    shape: "path in one table row, defect in another (must pass)",
    body: [
      "| Component | Status |",
      "| --- | --- |",
      "| server/src/audit | audited |",
      "| behavior on bypass | changed |",
    ].join("\n"),
  },
  {
    // Path in the heading, regression prose on the immediately following nonblank
    // line with no blank line between them. Passes only because the heading is
    // checked separately and does not accumulate: under blank-line-only assembly
    // the two lines would be one paragraph and D2 would fire (path + defect).
    shape: "heading with path, regression prose on the immediately following nonblank line with no blank line (must pass)",
    body: [
      "## Audit in server/src/audit",
      "The regression in this component has been corrected.",
    ].join("\n"),
  },
];

describe("disclosure guard — checker behaviour", () => {
  it("is present and executable", () => {
    const help = spawnSync(CHECKER, ["--help"], { cwd: REPO_ROOT, encoding: "utf8" });
    // --help is a usage exit (2), the same convention scripts/check-ai-tells.sh
    // uses: 2 means "I could not run", never "I found something".
    expect(help.status, help.stdout + help.stderr).toBe(2);
  });

  it("exits 2 on a path that does not exist, so a broken call is not read as clean", () => {
    const missing = spawnSync(CHECKER, [join(tmpdir(), "no-such-disclosure-input.md")], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    });
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain("path does not exist");
  });

  it("refuses every entry in the must-fail corpus", () => {
    const passed: string[] = [];
    for (const entry of MUST_FAIL) {
      const run = runChecker(entry.body);
      if (run.status !== 1) passed.push(entry.shape);
    }
    expect(
      passed,
      `these disclosure shapes were NOT refused: ${passed.join("; ")}`,
    ).toEqual([]);
  });

  it("accepts every entry in the must-pass corpus", () => {
    const refused: string[] = [];
    for (const entry of MUST_PASS) {
      const run = runChecker(entry.body);
      if (run.status !== 0) refused.push(entry.shape);
    }
    expect(
      refused,
      `these honest shapes were refused, which is how a gate gets switched off: ${refused.join("; ")}`,
    ).toEqual([]);
  });

  it("catches the class-plus-scope shape that names no file at all", () => {
    // Called out separately because it is the hardest of the three real
    // instances and the one a future simplification is most likely to drop.
    const run = runChecker("Tip verification in the audit chain accepts a replayed head.");
    expect(run.status).toBe(1);
    expect(run.stdout).toContain("D8-LOCALIZED");
  });

  it("never echoes the text it refused", () => {
    const secret = "zzqqx-marker-that-must-not-appear";
    const run = runChecker(
      `An attacker can replay the head. Marker ${secret} sits in the same sentence.`,
    );
    expect(run.status).toBe(1);
    // The report is written into build logs, and build logs on a public
    // repository are public. A guard that quotes the body back relocates the
    // disclosure instead of preventing it.
    expect(run.stdout).not.toContain(secret);
    expect(run.stderr).not.toContain(secret);
  });

  it("states its own bound instead of implying full coverage", () => {
    const run = runChecker("Adds a bounded age check on the relying side.");
    expect(run.status).toBe(0);
    expect(run.stdout).toContain("BOUND:");
  });

  it("masks the register-id shape the rule sanctions", () => {
    for (const id of ["IC-05-DG", "C12-REPLAY", "SYNC-APPEND-01", "O-02", "QI-SIBLING-02"]) {
      expect(id, "register-id shape drifted from the checker's mask").toMatch(
        REGISTER_ID_SHAPE,
      );
      expect(runChecker(`Closes ${id}.`).status).toBe(0);
    }
  });

  it("accepts a source path on both pr-body and test-header when defect language is absent", () => {
    const body = "Covers the barrel export in server/src/audit/index.ts.";
    expect(runChecker(body, "pr-body").status).toBe(0);
    expect(runChecker(body, "test-header").status).toBe(0);
  });

  it("still refuses a source path when defect language shares the paragraph, on both surfaces", () => {
    const body =
      "Covers server/src/audit/index.ts, where the regression was introduced.";
    expect(runChecker(body, "pr-body").status).toBe(1);
    expect(runChecker(body, "test-header").status).toBe(1);
  });

  it("accepts a source-tree directory path when defect language is absent", () => {
    // The second scrub of the triggering wave carried a directory and no
    // filename. A source-tree directory alone now passes; it fails only with
    // defect language in the same paragraph.
    const run = runChecker("The new scan here is bounded to server/src/mesh.");
    expect(run.status).toBe(0);
    // But the same directory with defect language in the paragraph fails.
    const withDefect = runChecker("The flaw here is in server/src/mesh, where the regression occurs.");
    expect(withDefect.status).toBe(1);
    expect(withDefect.stdout).toContain("D2-CODEPATH");
    // Naming a directory that is not a source tree still passes: reddening
    // scripts/ or .github/ would locate nothing and would red honest bodies.
    expect(runChecker("Adds the job under .github/workflows.").status).toBe(0);
  });

  it("refuses a residual-instance claim beside a scope, with no file named", () => {
    const run = runChecker(
      "A further instance of the same class exists outside the mesh layer.",
    );
    expect(run.status).toBe(1);
    expect(run.stdout).toContain("D8-LOCALIZED");
  });

  it("refuses a piece of state described as unbounded, with no locator at all", () => {
    // D10 is the only rule that stands alone without a scope. The shape it
    // catches names no path and no subsystem, only mechanism.
    const run = runChecker("The shared collection those entries land in is uncapped.");
    expect(run.status).toBe(1);
    expect(run.stdout).toContain("D10-MECHANISM");
    expect(runChecker("The drop path writes into a shared unbounded collection.").status).toBe(1);
  });

  it("separates protection-absence from capability-absence", () => {
    // The load-bearing distinction inside MUST-NEVER #9. Saying a component
    // LACKS A PROTECTION is a defect description. Saying a CAPABILITY IS ABSENT
    // OR UNPROVEN is an honesty obligation that must never be softened, so it
    // must never be refused. If a future widening of MECHANISM_NEG breaks this,
    // the guard has started punishing the honest half of the rule it enforces.
    for (const honest of [
      "This capability is unproven on Linux.",
      "Linux egress enforcement is not implemented.",
      "The wrapping path is untested on this platform and the row stays partial.",
    ]) {
      expect(runChecker(honest).status, `refused an honest bound: ${honest}`).toBe(0);
    }
    for (const disclosure of [
      "The retention map is uncapped.",
      "Entries are appended ungoverned.",
    ]) {
      expect(runChecker(disclosure).status, `passed a disclosure: ${disclosure}`).toBe(1);
    }
  });
});

function trackedTestFiles(): string[] {
  const out = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z", "server/test"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return out
    .split("\0")
    .filter((p) => p.endsWith(".test.ts") || p.endsWith(".test.tsx"))
    .sort();
}

function parseBaseline(): Map<string, number> {
  const parsed = new Map<string, number>();
  for (const raw of readFileSync(BASELINE_PATH, "utf8").split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const [rule, count] = line.split(/\s+/);
    if (!rule || !/^[0-9]+$/.test(count ?? "")) {
      throw new Error(`disclosure-baseline.txt: unparseable row: ${rule ?? "(empty)"}`);
    }
    parsed.set(rule, Number(count));
  }
  return parsed;
}

describe("disclosure guard — in-repo test-header ratchet", () => {
  // Explicit timeout. This scans the header of every tracked test file through
  // a shell checker, which is process-heavy by construction: roughly twenty
  // seconds on an idle Mac and more on a builder running the rest of the suite
  // beside it. It first ran at the 30s default and timed out on the Linux
  // builder while passing locally, which is the worst failure shape available
  // (green where it is written, red where it is enforced). The ceiling is
  // deliberately far above the real cost; it is a stop, not a budget.
  it("keeps the per-rule hit total in committed test headers at or below the baseline", () => {
    const files = trackedTestFiles();
    expect(files.length).toBeGreaterThan(0);

    // The header boundary is defined by the checker's own `--extract header`
    // stage, not re-implemented here. Two stages that must agree on a structure
    // share one parse; a second copy in TypeScript would be the hand-mirrored
    // shape this repository already has a rule against, and it would drift the
    // first time either side learned a new comment style.
    const run = spawnSync(
      CHECKER,
      [
        "--surface",
        "test-header",
        "--extract",
        "header",
        "--format",
        "tsv",
        ...files,
      ],
      { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
    );
    expect(run.status, run.stderr).not.toBe(2);

    const observed = new Map<string, number>();
    for (const row of run.stdout.split("\n")) {
      if (row.trim() === "") continue;
      const rule = row.split("\t")[1];
      if (!rule) continue;
      observed.set(rule, (observed.get(rule) ?? 0) + 1);
    }

    const baseline = parseBaseline();
    const rules = new Set<string>([...baseline.keys(), ...observed.keys()]);
    const worse: string[] = [];
    const better: string[] = [];
    for (const rule of [...rules].sort()) {
      const was = baseline.get(rule) ?? 0;
      const now = observed.get(rule) ?? 0;
      if (now > was) worse.push(`${rule}: ${was} -> ${now}`);
      if (now < was) better.push(`${rule}: ${was} -> ${now}`);
    }

    expect(
      worse,
      [
        "A test-file header gained a disclosure shape.",
        "No path is named here on purpose: a permanent index of which headers",
        "trip this check is the thing the rule forbids. To find it, run the",
        "checker over the test files THIS change touched:",
        "  scripts/check-disclosure.sh --surface test-header --extract header <file>...",
        "Then rewrite the header as the capability under test plus a bare",
        "private-register id. Regressed rules: " + worse.join(", "),
      ].join("\n"),
    ).toEqual([]);

    expect(
      better,
      [
        "Fewer hits than the baseline, which is good and must be locked in.",
        "Lower the counts in server/test/structure/disclosure-baseline.txt to",
        "the observed values IN THIS PR. A stale high baseline leaves a gap a",
        "later regression hides under: " + better.join(", "),
      ].join("\n"),
    ).toEqual([]);
  }, 300_000);
});

describe("disclosure guard — CI wiring", () => {
  it("gates pull-request descriptions on every edit, not only on open", () => {
    const workflow = readFileSync(WORKFLOW_PATH, "utf8");
    // `edited` is the load-bearing trigger. Two of the three real instances
    // were introduced by EDITING a description that had already passed review,
    // so a workflow that only fires on `opened` would have caught one of three.
    expect(workflow).toContain("edited");
    expect(workflow).toContain("scripts/check-disclosure.sh");
    expect(workflow).toMatch(/^on:\s*\n\s+pull_request:/m);
  });

  it("reads the description from the environment, never from a run-step expression", () => {
    const workflow = readFileSync(WORKFLOW_PATH, "utf8");
    // A description is attacker-controlled text on a fork pull request.
    // Interpolating it into a `run:` block splices it into the shell; passing
    // it through `env:` keeps it a value. Failure mode if this inverts: a
    // description containing shell metacharacters executes on the runner.
    expect(workflow).toContain("PR_BODY: ${{ github.event.pull_request.body }}");
    const bodyRefs = workflow
      .split("\n")
      .filter((l) => l.includes("github.event.pull_request.body"));
    expect(bodyRefs.length).toBeGreaterThan(0);
    for (const line of bodyRefs) {
      expect(line, "the description may only be bound as an env value").toMatch(
        /^\s+PR_BODY:\s*\$\{\{\s*github\.event\.pull_request\.body\s*\}\}\s*$/,
      );
    }
    // pull_request_target would run this with a writable token against
    // fork-controlled content. It is never the right trigger for a text check.
    // Matched as a TRIGGER KEY, not as a substring: the workflow's own header
    // names the trigger while explaining why it is not used, and a substring
    // assertion would forbid saying so.
    expect(workflow).not.toMatch(/^\s*pull_request_target\s*:/m);
  });
});
