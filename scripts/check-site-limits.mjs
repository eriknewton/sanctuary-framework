#!/usr/bin/env node
// check-site-limits.mjs: the built website renders every Assurance Matrix limit
// from data, and every "Limits" link lands on that rendered limit.
//
// WHY THIS EXISTS (2026-10-18): the public site's capability limits were
// paraphrased by hand from ASSURANCE_MATRIX.md, and three review rounds in a row
// found a hand-copied list missing one more bound from its row. The site now
// renders docs/_data/assurance_matrix.json (written by
// scripts/export-assurance-matrix.mjs) on /limits/, and pages link there through
// docs/_includes/matrix-evidence.html. This script checks the BUILT site, because
// only the rendered HTML shows what a reader and an agent actually receive.
//
// Invariants, each fail-closed (exit 1 on any breach; exit 2 on usage error):
//   1. COMPLETE RENDER. /limits/ carries exactly one row section per matrix row,
//      in matrix order, and no row the data does not have.
//   2. VERBATIM BOUNDS. Each section's decoded "Known limits" text is non-empty
//      and byte-equal to the row's `bounds`; status and platform are byte-equal
//      too. Liquid's `escape` is the only transform the template applies, so the
//      decode here reverses exactly that set (& < > " ').
//   3. EVERY LINK RESOLVES. Every href into /limits/# on every built page names a
//      rendered row id, and the evidence word printed beside it is that row's
//      status, so a page can never show a status the matrix does not hold.
//   4. NO SILENT GAP. A "MATRIX ROW MISSING" or "MATRIX DATA MISSING" marker on
//      any page (the include's and the page's fail-closed output) fails the run.
//
// Field names and the anchor rule must match docs/limits.html and
// docs/_includes/matrix-evidence.html (`row.claim | slugify`).
//
// Usage: node scripts/check-site-limits.mjs <built-site-dir>

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// Must match SITE_DATA_JSON_REL in scripts/export-assurance-matrix.mjs.
const SITE_DATA_JSON_REL = "docs/_data/assurance_matrix.json";
const MISSING_MARKERS = ["MATRIX ROW MISSING", "MATRIX DATA MISSING"];

const problems = [];
function problem(msg) {
  problems.push(msg);
}

// Reverses Liquid's `escape` (Ruby CGI.escapeHTML): & < > " and ' only. Any other
// entity in a rendered bounds cell would mean the template transformed the text,
// which invariant 2 treats as a mismatch rather than decoding it away.
function decodeEscape(text) {
  return text
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&");
}

function htmlFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...htmlFiles(p));
    else if (name.endsWith(".html")) out.push(p);
  }
  return out;
}

function main() {
  const siteArg = process.argv[2];
  if (!siteArg || process.argv.length > 3) {
    console.error("usage: node scripts/check-site-limits.mjs <built-site-dir>");
    process.exit(2);
  }
  const site = resolve(siteArg);
  const limitsPath = join(site, "limits", "index.html");
  if (!existsSync(limitsPath)) {
    console.error(`CHECK SITE LIMITS: FAIL. ${relative(process.cwd(), limitsPath)} was not built.`);
    process.exit(1);
  }
  const rows = JSON.parse(readFileSync(join(REPO_ROOT, SITE_DATA_JSON_REL), "utf8")).rows;
  if (!Array.isArray(rows) || rows.length === 0) problem(`${SITE_DATA_JSON_REL} has no rows.`);

  // Invariants 1 and 2: parse each rendered row section in document order.
  const limitsHtml = readFileSync(limitsPath, "utf8");
  const sectionRe =
    /<section class="limits-row" id="([^"]*)"[^>]*>\s*<h2 id="[^"]*">([\s\S]*?)<\/h2>\s*<dl class="limits-fields"><dt>Platform<\/dt><dd class="matrix-platform">([\s\S]*?)<\/dd><dt>Status<\/dt><dd class="matrix-status">([\s\S]*?)<\/dd><dt>Known limits<\/dt><dd class="matrix-bounds">([\s\S]*?)<\/dd><\/dl>/g;
  const rendered = [...limitsHtml.matchAll(sectionRe)].map((m) => ({
    id: m[1],
    claim: decodeEscape(m[2]),
    platform: decodeEscape(m[3]),
    status: decodeEscape(m[4]),
    bounds: decodeEscape(m[5]),
  }));
  const sectionCount = (limitsHtml.match(/<section class="limits-row"/g) || []).length;
  if (sectionCount !== rendered.length) {
    problem(`/limits/ has ${sectionCount} row sections but only ${rendered.length} match the rendered shape.`);
  }
  if (rendered.length !== rows.length) {
    problem(`/limits/ renders ${rendered.length} rows; the matrix data has ${rows.length}.`);
  }
  const byId = new Map();
  rows.forEach((row, i) => {
    const r = rendered[i];
    if (!r) return;
    if (r.claim !== row.claim) problem(`/limits/ row ${i + 1} is "${r.claim}", data row is "${row.claim}".`);
    if (!row.bounds || !r.bounds) problem(`"${row.claim}": empty bounds.`);
    if (r.bounds !== row.bounds) problem(`"${row.claim}": rendered bounds differ from the matrix row.`);
    if (r.status !== row.status) problem(`"${row.claim}": rendered status "${r.status}" is not "${row.status}".`);
    if (r.platform !== row.platform) problem(`"${row.claim}": rendered platform differs from the matrix row.`);
    if (!r.id) problem(`"${row.claim}": empty anchor id.`);
    if (byId.has(r.id)) problem(`anchor "${r.id}" is used by two rows.`);
    byId.set(r.id, row);
  });

  // Invariants 3 and 4 over every built page.
  let links = 0;
  const linkRe =
    /<span class="matrix-evidence">[^<]*?: ([^<]*?)\. <a href="[^"#]*\/limits\/#([^"]*)"[^>]*>Limits<\/a><\/span>/g;
  for (const file of htmlFiles(site)) {
    const html = readFileSync(file, "utf8");
    const rel = relative(site, file);
    for (const marker of MISSING_MARKERS) if (html.includes(marker)) problem(`${rel}: contains "${marker}".`);
    const hrefs = [...html.matchAll(/href="[^"#]*\/limits\/#([^"]*)"/g)].map((m) => m[1]);
    const spans = [...html.matchAll(linkRe)];
    if (spans.length !== hrefs.length) {
      problem(`${rel}: ${hrefs.length} links into /limits/ but ${spans.length} come from the evidence include.`);
    }
    for (const [, status, id] of spans) {
      links++;
      const row = byId.get(id);
      if (!row) {
        problem(`${rel}: Limits link to #${id} has no rendered row.`);
        continue;
      }
      if (decodeEscape(status) !== row.status) {
        problem(`${rel}: evidence word "${status}" beside #${id} is not the row's status "${row.status}".`);
      }
    }
  }

  if (problems.length > 0) {
    for (const p of problems) console.error(`CHECK SITE LIMITS: FAIL. ${p}`);
    process.exit(1);
  }
  console.log(`CHECK SITE LIMITS: ${rendered.length} rows rendered verbatim; ${links} Limits links resolve with matching status.`);
}

main();
