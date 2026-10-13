#!/usr/bin/env node
// export-assurance-matrix.mjs: machine-readable twin of ASSURANCE_MATRIX.md.
//
// WHY THIS EXISTS (2026-10-12):
// An evaluating agent (an A2A card consumer, a connector directory, a procurement
// script) reads JSON, not a Markdown table. ASSURANCE_MATRIX.md stays the ONLY
// truth source; this script derives two public files from it and from the root
// README, and CI fails when either file drifts from its sources:
//
//   docs/assurance-matrix.json          every row of the matrix, same words
//   docs/.well-known/product-facts.json name, license, install/verify/uninstall
//                                       commands, per-platform status, bounds
//
// Invariants, each enforced below and each fail-closed (exit 1):
//   1. DETERMINISM. Same tree in, same bytes out: stable key order, rows in
//      matrix order, two-space indent, trailing newline, no timestamps. The only
//      tree-dependent field is `source_commit`, written ONLY under `--stamp`.
//      Committed files are never stamped; `--check` compares against the
//      unstamped output, so a stamped committed file fails the check by design.
//   2. PARSE PARITY. The table is read with the same semantics as
//      scripts/check-assurance-matrix.mjs (pipe rows, header detection, exactly
//      six cells, link extraction, repo-relative link resolution) so the guard and
//      the twin can never disagree about what a row says. The guard runs its own
//      main() on import and exports nothing, so the semantics are mirrored here
//      and pinned on both sides rather than imported.
//   3. NO NEW CLAIMS. Every string under `rows` in the twin, and every field of
//      the product-facts file, is a verbatim substring of
//      ASSURANCE_MATRIX.md, README.md, or server/package.json (the packet-named
//      source for the npm fields), or a repo-relative path that exists in the
//      tree. A string that is none of these is a claim the Markdown does not make,
//      and the export fails rather than publishing it. The twin's `schema` and
//      `source` fields are this script's own identifiers (pinned above), not claims.
//   4. STATUS VOCABULARY. A row's status must be one of the values the matrix's
//      own "Status enum:" line declares; the script never invents one.
//
// Public-surface rules apply: the JSON is served from the GitHub Pages docs/ tree,
// so it carries the matrix's bare defect ids and nothing more (AGENTS.md
// MUST-NEVER #9). docs/.well-known/ is a dot-directory that Jekyll drops unless
// docs/_config.yml lists it under `include:`; that config change is owned by a
// separate packet and is noted in this packet's report.
//
// Usage:
//   node scripts/export-assurance-matrix.mjs            write both files
//   node scripts/export-assurance-matrix.mjs --check    exit 1 with a diff if stale
//   node scripts/export-assurance-matrix.mjs --stamp    also write source_commit
// Exit codes: 0 = written or current; 1 = stale, unparseable, or unsourced text.

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MATRIX_REL = "ASSURANCE_MATRIX.md";
const README_REL = "README.md";
const SERVER_PACKAGE_REL = "server/package.json";
const SECURITY_POLICY_REL = "SECURITY.md";
const AUDIT_DIR_REL = "docs/audit/";
const MATRIX_JSON_REL = "docs/assurance-matrix.json";
const FACTS_JSON_REL = "docs/.well-known/product-facts.json";

const MATRIX_SCHEMA = "sanctuary-assurance-matrix/v1";
const FACTS_SCHEMA = "sanctuary-product-facts/v1";

// Column headers and the JSON field each one feeds. The header row must match
// the column headers in ASSURANCE_MATRIX.md exactly, and the six-column shape
// must match the `cells.length !== 6` check in scripts/check-assurance-matrix.mjs;
// a header change is a schema change and must fail here, not misalign silently.
const EXPECTED_HEADERS = ["Claim", "Platform", "Status", "Evidence", "Known Gap", "Next Proof Needed"];
const FIELD_FOR_HEADER = {
  Claim: "claim",
  Platform: "platform",
  Status: "status",
  Evidence: "evidence",
  "Known Gap": "bounds",
  "Next Proof Needed": "next",
};

// Structural strings that are not claims about the product and are therefore
// exempt from the no-new-claims check: the two schema identifiers only. Keep
// this list this short; anything added here is text the sources do not carry.
const EXEMPT_STRINGS = new Set([MATRIX_SCHEMA, FACTS_SCHEMA]);

function fail(message) {
  console.error(`EXPORT ASSURANCE MATRIX: FAIL. ${message}`);
  process.exit(1);
}

function readRepoFile(rel) {
  const abs = join(REPO_ROOT, rel);
  if (!existsSync(abs)) fail(`${rel} not found at ${abs}.`);
  return readFileSync(abs, "utf8");
}

// Target extraction uses the SAME regex as relativeLinkTargets() in
// scripts/check-assurance-matrix.mjs (`/\]\(([^)]+)\)/g`, anchored on the `](`
// pair), so the twin and the guard see exactly the same set of hrefs, including
// a link whose label contains `]`. The label is then recovered by walking back
// from the `]` to its matching `[` by bracket depth; it is carried as display
// text only and never resolved. The anchor is stripped only for resolution; the
// href is carried as written so a reader lands where the matrix points.
function evidenceLinks(cell) {
  const links = [];
  const linkRe = /\]\(([^)]+)\)/g;
  let m;
  while ((m = linkRe.exec(cell)) !== null) {
    const href = m[1].trim();
    if (!href) continue;
    let depth = 0;
    let start = -1;
    for (let i = m.index; i >= 0; i--) {
      if (cell[i] === "]") depth++;
      else if (cell[i] === "[" && --depth === 0) {
        start = i;
        break;
      }
    }
    const label = start >= 0 ? cell.slice(start + 1, m.index) : "";
    links.push({ label, href });
  }
  return links;
}

// Mirrors the Invariant 1 resolver in scripts/check-assurance-matrix.mjs: http(s)
// and mailto targets are external and skipped; a repo-relative target must not be
// absolute, must not escape the repository, and must exist. Any disagreement
// between this function and the guard would let the twin cite what the guard
// rejects, so the three checks are kept in the same order with the same tests.
function resolveRepoRelative(target) {
  const bare = target.split("#")[0];
  if (!bare) return { kind: "anchor" };
  if (/^https?:\/\//i.test(bare) || /^mailto:/i.test(bare)) return { kind: "external" };
  if (bare.startsWith("/")) return { kind: "invalid", why: "absolute path" };
  const abs = resolve(REPO_ROOT, bare);
  const withinRepo = abs === REPO_ROOT || abs.startsWith(REPO_ROOT + sep);
  if (!withinRepo) return { kind: "invalid", why: "escapes the repository" };
  if (!existsSync(abs)) return { kind: "invalid", why: "does not resolve" };
  return { kind: "repo", abs };
}

function parseStatusEnum(matrixText) {
  const line = matrixText.split("\n").find((l) => /^Status enum:/.test(l));
  if (!line) fail(`${MATRIX_REL} has no "Status enum:" line; the status vocabulary must come from the matrix.`);
  const values = [...line.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
  if (values.length === 0) fail(`${MATRIX_REL} "Status enum:" line names no backticked values.`);
  return values;
}

// Row parsing mirrors main() in scripts/check-assurance-matrix.mjs: only
// pipe-prefixed lines are table lines, the header row starts the table, the
// separator row is skipped, and a row with other than six cells fails loudly.
// One addition the guard does not make: a second table fails here, because the
// twin models exactly one.
function parseMatrix(matrixText) {
  const statusEnum = parseStatusEnum(matrixText);
  const rows = [];
  let inTable = false;
  let headerSeen = false;
  for (const raw of matrixText.split("\n")) {
    const line = raw.trimEnd();
    if (!line.startsWith("|")) {
      inTable = false;
      continue;
    }
    if (/^\|\s*Claim\s*\|/.test(line)) {
      const headers = line.split("|").slice(1, -1).map((c) => c.trim());
      if (JSON.stringify(headers) !== JSON.stringify(EXPECTED_HEADERS)) {
        fail(`${MATRIX_REL} header row is ${JSON.stringify(headers)}; expected ${JSON.stringify(EXPECTED_HEADERS)}.`);
      }
      if (headerSeen) fail(`${MATRIX_REL} has more than one table; the twin models exactly one.`);
      headerSeen = true;
      inTable = true;
      continue;
    }
    if (/^\|\s*-+\s*\|/.test(line)) continue;
    if (!inTable) continue;
    const cells = line.split("|").slice(1, -1).map((c) => c.trim());
    if (cells.length !== 6) {
      fail(`row after "${cells[0] ?? "?"}" has ${cells.length} columns, expected exactly 6 (a literal '|' in a cell must be escaped as '\\|').`);
    }
    const row = {};
    EXPECTED_HEADERS.forEach((header, i) => {
      row[FIELD_FOR_HEADER[header]] = cells[i];
    });
    if (!statusEnum.includes(row.status)) {
      fail(`"${row.claim}" has status "${row.status}", which is not in the matrix's Status enum (${statusEnum.join(", ")}).`);
    }
    const links = evidenceLinks(row.evidence);
    for (const { href } of links) {
      const r = resolveRepoRelative(href);
      if (r.kind === "invalid") fail(`"${row.claim}": evidence link ${r.why}: ${href}`);
    }
    // The raw cell is kept beside the link list because three proven rows cite a
    // dated drill in prose outside any link; the guard's drill rule keys on that
    // prose, and a twin that dropped it would show a drill-less proven row.
    rows.push({
      claim: row.claim,
      platform: row.platform,
      status: row.status,
      evidence: links,
      evidence_text: row.evidence,
      bounds: row.bounds,
      next: row.next,
    });
  }
  if (rows.length === 0) fail(`no assurance-matrix rows parsed; the table shape may have changed.`);
  return { rows, statusEnum };
}

// Pulls one fenced-code line out of a README section by text match. The install
// command is copied, never typed here, so a README edit is the only way to
// change what the facts file tells an agent to run.
function readmeSectionCommand(readmeText, headingRe, lineRe, what) {
  const lines = readmeText.split("\n");
  const start = lines.findIndex((l) => headingRe.test(l));
  if (start < 0) fail(`${README_REL} has no section matching ${headingRe} (needed for ${what}).`);
  const level = lines[start].match(/^#+/)[0].length;
  for (let i = start + 1; i < lines.length; i++) {
    const h = lines[i].match(/^(#+)\s/);
    if (h && h[1].length <= level) break;
    // A fence line is markup, never a command; without this skip a permissive
    // lineRe would capture "```bash" as the command.
    if (/^```/.test(lines[i])) continue;
    if (lineRe.test(lines[i])) return lines[i].trim();
  }
  fail(`${README_REL} section at line ${start + 1} has no line matching ${lineRe} (needed for ${what}).`);
}

function gitHead() {
  const r = spawnSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf8" });
  if (r.status !== 0) fail(`git rev-parse HEAD failed: ${r.stderr}`);
  return r.stdout.trim();
}

function collectStrings(value, path, out) {
  if (typeof value === "string") {
    out.push({ path, value });
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => collectStrings(v, `${path}[${i}]`, out));
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) collectStrings(v, `${path}.${k}`, out);
  }
}

// Invariant 3: every leaf string is a verbatim substring of a named source text.
// The one escape is deliberately narrow: a string that is NOT in any source
// passes only if it is one of SELF_PATHS (the two files the facts point at by
// their own names, which no source mentions) AND that path exists in the tree.
// Any other existing path (say a directory name that happens to exist) still
// fails, so the escape cannot smuggle a claim. Checked on both files before
// anything is written, so a drifted README section or a typo in a constant
// above cannot ship.
const SELF_PATHS = new Set([MATRIX_JSON_REL, SECURITY_POLICY_REL]);
function assertSourced(label, data, sources, extraKeys = []) {
  const leaves = [];
  collectStrings(data, label, leaves);
  for (const key of extraKeys) leaves.push({ path: `${label}.<key>`, value: key });
  for (const { path, value } of leaves) {
    if (EXEMPT_STRINGS.has(value)) continue;
    if (sources.some((s) => s.includes(value))) continue;
    if (SELF_PATHS.has(value) && resolveRepoRelative(value).kind === "repo") continue;
    fail(`${path} carries text absent from ${sources.length === 1 ? MATRIX_REL : "the sources"} and not a declared self path: ${JSON.stringify(value)}`);
  }
}

function serialize(obj) {
  return JSON.stringify(obj, null, 2) + "\n";
}

function build(stamp) {
  const matrixText = readRepoFile(MATRIX_REL);
  const readmeText = readRepoFile(README_REL);
  const serverPackageText = readRepoFile(SERVER_PACKAGE_REL);
  const serverPackage = JSON.parse(serverPackageText);
  for (const field of ["name", "mcpName", "license"]) {
    if (typeof serverPackage[field] !== "string" || !serverPackage[field]) {
      fail(`${SERVER_PACKAGE_REL} has no string "${field}".`);
    }
  }
  const { rows } = parseMatrix(matrixText);

  const matrixJson = {
    schema: MATRIX_SCHEMA,
    source: MATRIX_REL,
    ...(stamp ? { source_commit: stamp } : {}),
    rows,
  };
  assertSourced("assurance-matrix", { rows }, [matrixText]);

  // Repository and homepage are the README's own literals; each is checked as a
  // substring below, so a URL change in the README is the only way to change it.
  const repository = "https://github.com/eriknewton/sanctuary-framework";
  const homepage = "https://sanctuaryprotocol.ai";
  // All three commands are copied from the README's Quickstart section, which
  // lists install, verify and uninstall as adjacent lines; each is matched by
  // its verb so a reordering of the block cannot swap them. A missing line fails
  // the export rather than falling back to a typed command.
  const QUICKSTART_RE = /^## Quickstart\s*$/;
  const install = readmeSectionCommand(
    readmeText,
    QUICKSTART_RE,
    /^npx -y @sanctuary-framework\/mcp-server protect\b/,
    "install command",
  );
  const verify = readmeSectionCommand(
    readmeText,
    QUICKSTART_RE,
    /^npx -y @sanctuary-framework\/mcp-server doctor --json\s*$/,
    "verify command",
  );
  const uninstall = readmeSectionCommand(
    readmeText,
    QUICKSTART_RE,
    /^npx -y @sanctuary-framework\/mcp-server uninstall\s*$/,
    "uninstall command",
  );

  // Each platform entry carries its row's Known Gap verbatim so that a reader
  // of the platform summary never sees a claim stronger than the row it came
  // from: "proven" for macOS still names what the row does not prove.
  const platforms = {};
  for (const row of rows) {
    (platforms[row.platform] ??= []).push({ claim: row.claim, status: row.status, bounds: row.bounds });
  }
  const bounds = rows
    .filter((row) => row.status !== "proven")
    .map((row) => ({ claim: row.claim, status: row.status, bounds: row.bounds }));

  const facts = {
    schema: FACTS_SCHEMA,
    ...(stamp ? { source_commit: stamp } : {}),
    name: "Sanctuary",
    license: serverPackage.license,
    repository,
    npm: { package: serverPackage.name, mcpName: serverPackage.mcpName },
    homepage,
    install,
    verify,
    uninstall,
    platforms,
    bounds,
    evidence_index: { repository, matrix: MATRIX_REL, matrix_json: MATRIX_JSON_REL, audit: AUDIT_DIR_REL },
    security_policy: SECURITY_POLICY_REL,
    generated_from: MATRIX_REL,
  };
  const factsForCheck = { ...facts };
  delete factsForCheck.source_commit;
  assertSourced("product-facts", factsForCheck, [matrixText, readmeText, serverPackageText], Object.keys(platforms));

  return [
    { rel: MATRIX_JSON_REL, text: serialize(matrixJson) },
    { rel: FACTS_JSON_REL, text: serialize(facts) },
  ];
}

function showDiff(rel, expectedText) {
  const dir = mkdtempSync(join(tmpdir(), "assurance-twin-"));
  const expectedPath = join(dir, "expected.json");
  try {
    writeFileSync(expectedPath, expectedText);
    const r = spawnSync("diff", ["-u", join(REPO_ROOT, rel), expectedPath], { encoding: "utf8" });
    if (r.error) {
      console.error(`(diff unavailable: ${r.error.message}; regenerate with: node scripts/export-assurance-matrix.mjs)`);
    } else {
      console.error(r.stdout.replace(expectedPath, `${rel} (regenerated)`));
    }
  } finally {
    unlinkSync(expectedPath);
    rmdirSync(dir);
  }
}

function main() {
  const args = new Set(process.argv.slice(2));
  const stamp = args.has("--stamp") ? gitHead() : null;
  const check = args.has("--check");
  for (const a of args) {
    if (a !== "--stamp" && a !== "--check") fail(`unknown argument ${a}.`);
  }
  if (check && stamp) fail(`--check compares against the unstamped output; do not pass --stamp with it.`);

  const outputs = build(stamp);
  let stale = 0;
  for (const { rel, text } of outputs) {
    const abs = join(REPO_ROOT, rel);
    if (check) {
      const current = existsSync(abs) ? readFileSync(abs, "utf8") : null;
      if (current === text) {
        console.log(`EXPORT ASSURANCE MATRIX: ${rel} is current.`);
        continue;
      }
      stale++;
      console.error(`EXPORT ASSURANCE MATRIX: ${rel} is ${current === null ? "missing" : "stale"}.`);
      if (current !== null) showDiff(rel, text);
    } else {
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, text);
      console.log(`EXPORT ASSURANCE MATRIX: wrote ${rel}.`);
    }
  }
  if (stale > 0) {
    console.error(`\nRegenerate with: node scripts/export-assurance-matrix.mjs (then commit the result).`);
    process.exit(1);
  }
  process.exit(0);
}

main();
