#!/usr/bin/env node
// check-assurance-matrix.mjs — structural guard on ASSURANCE_MATRIX.md.
//
// WHY THIS EXISTS (2026-08-08):
// The 46-agent inert-capability sweep found that ASSURANCE_MATRIX row 17 marked
// Linux egress enforcement `proven` while the shipped daemon installs no kernel
// enforcement at all. The row cited integration tests that genuinely exist and
// pass — they prove the modules, not the shipped boot path. The thesis-gate rule
// ("no capability claim without drill evidence on the platform that matters") had
// been applied to exactly one capability (the macOS wall) and never generalized.
// This guard generalizes it mechanically so a platform-enforcement claim can never
// reach `proven` on test-only evidence again.
//
// It enforces two invariants and fails closed (exit 1) on any violation:
//   1. LINK RESOLUTION. Every repo-relative markdown link in the Evidence column
//      resolves to a file that exists. Catches doc drift (a `proven` row pointing
//      at a moved or deleted test/drill artifact).
//   2. ENFORCEMENT CLAIMS NEED A DRILL. A row whose Status is `proven` AND that is
//      a platform-enforcement claim (concrete OS/host/guest platform, or a Claim
//      naming enforcement/egress/containment/reboot/install) MUST cite drill
//      evidence: a link under docs/audit/, OR the word "drill" next to a
//      YYYY-MM-DD date. A green unit-test suite is not sufficient evidence that a
//      shipped enforcement path enforces; a captured drill is.
//
// This guard cannot catch a semantic lie inside a drill doc; it makes the cheap,
// mechanical failure modes (dead links, tests-standing-in-for-a-drill) impossible.
//
// Usage: node scripts/check-assurance-matrix.mjs
// Exit codes: 0 = all invariants hold; 1 = one or more violations.

import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MATRIX_PATH = join(REPO_ROOT, "ASSURANCE_MATRIX.md");

// A row is a platform-enforcement claim when its CLAIM names an enforcement-class
// behavior. The trigger is deliberately on the claim, not the platform: a
// server/format row (e.g. the transparency verifier) may name "macOS helper-as-
// signer" in its platform while making no enforcement claim, and such rows are
// legitimately proven by tests. Enforcement claims are the ones a passing test
// suite cannot prove — only a drill on the real platform can. Keep this list in
// sync with the assurance-discipline section of AGENTS.md; the two are a cross-file
// contract. The platform column then tells you WHICH platform's drill is required.
const ENFORCEMENT_CLAIM_RE =
  /\b(enforcement|egress|containment|reboot|install|firewall|jail|confine|wrap)\b/i;

// Drill evidence = a captured artifact under docs/audit/, OR the token "drill"
// accompanied by an ISO date. Either proves someone ran the real thing on a date.
const DRILL_DOC_RE = /docs\/audit\//i;
const DATED_DRILL_RE = /drill[\s\S]{0,80}?\d{4}-\d{2}-\d{2}|\d{4}-\d{2}-\d{2}[\s\S]{0,80}?drill/i;

// Extract repo-relative targets from markdown links `[text](target)`; skip http(s)
// and anchor-only links.
function relativeLinkTargets(cell) {
  const targets = [];
  const linkRe = /\]\(([^)]+)\)/g;
  let m;
  while ((m = linkRe.exec(cell)) !== null) {
    const target = m[1].trim().split("#")[0];
    if (!target) continue;
    if (/^https?:\/\//i.test(target)) continue;
    if (/^mailto:/i.test(target)) continue;
    targets.push(target);
  }
  return targets;
}

function main() {
  if (!existsSync(MATRIX_PATH)) {
    console.error(`FAIL: ${MATRIX_PATH} not found.`);
    process.exit(1);
  }
  const lines = readFileSync(MATRIX_PATH, "utf8").split("\n");

  // The matrix table rows are pipe-delimited lines with the exact 6-column header
  // "Claim | Platform | Status | Evidence | Known Gap | Next Proof Needed".
  const violations = [];
  let inTable = false;
  let rowNum = 0;

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (!line.startsWith("|")) {
      inTable = false;
      continue;
    }
    // Header row: mark the table start and skip.
    if (/^\|\s*Claim\s*\|/.test(line)) {
      inTable = true;
      continue;
    }
    // Separator row (|---|---|...): skip.
    if (/^\|\s*-+\s*\|/.test(line)) continue;
    if (!inTable) continue;

    // Split into cells; a leading and trailing pipe produce empty edge cells.
    const cells = line.split("|").slice(1, -1).map((c) => c.trim());
    if (cells.length < 6) {
      violations.push(`Row after "${cells[0] ?? "?"}" has ${cells.length} columns, expected 6.`);
      continue;
    }
    rowNum++;
    const [claim, platform, status, evidence] = cells;

    // Invariant 1: every repo-relative evidence link resolves.
    for (const target of relativeLinkTargets(evidence)) {
      const abs = resolve(REPO_ROOT, target);
      if (!existsSync(abs)) {
        violations.push(`"${claim}": evidence link does not resolve: ${target}`);
      }
    }

    // Invariant 2: a proven platform-enforcement claim must cite a drill.
    if (status.toLowerCase() === "proven") {
      const isEnforcement = ENFORCEMENT_CLAIM_RE.test(claim);
      if (isEnforcement) {
        const hasDrill = DRILL_DOC_RE.test(evidence) || DATED_DRILL_RE.test(evidence);
        if (!hasDrill) {
          violations.push(
            `"${claim}" (${platform}) is marked \`proven\` but cites no drill evidence. ` +
              `A platform-enforcement claim needs a docs/audit/ drill link or a dated "drill" ` +
              `citation, not test/PR links alone. Downgrade to \`partial\` or add the drill.`
          );
        }
      }
    }
  }

  if (rowNum === 0) {
    console.error("FAIL: no assurance-matrix rows parsed; the table shape may have changed.");
    process.exit(1);
  }

  if (violations.length > 0) {
    console.error(`ASSURANCE MATRIX GUARD: ${violations.length} violation(s) across ${rowNum} rows.\n`);
    for (const v of violations) console.error(`  - ${v}`);
    console.error(
      `\nWhy this guard exists: ASSURANCE_MATRIX row 17 sat at \`proven\` on test-only ` +
        `evidence while Linux enforcement was never wired. See scripts/check-assurance-matrix.mjs header.`
    );
    process.exit(1);
  }

  console.log(`ASSURANCE MATRIX GUARD: OK. ${rowNum} rows; all evidence links resolve; every proven enforcement claim cites a drill.`);
  process.exit(0);
}

main();
