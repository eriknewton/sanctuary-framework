/**
 * The public website renders capability limits from the Assurance Matrix data, never from hand-copied prose.
 *
 * Pages name a matrix row by its exact claim through docs/_includes/matrix-evidence.html; docs/limits.html
 * renders every row's bounds verbatim. These source-level checks pair with scripts/check-site-limits.mjs,
 * which checks the built site.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const docs = join(root, "docs");
const read = (rel: string) => readFileSync(join(root, rel), "utf8");

interface Row {
  claim: string;
  status: string;
  bounds: string;
}
// Must match SITE_DATA_JSON_REL in scripts/export-assurance-matrix.mjs.
const rows: Row[] = JSON.parse(read("docs/_data/assurance_matrix.json")).rows;

// Jekyll's default `slugify` for ASCII text: every run of characters other than
// letters and digits becomes one hyphen, the result is lowercased, and leading
// and trailing hyphens are dropped. Must match the `row.claim | slugify` anchors
// in docs/limits.html and docs/_includes/matrix-evidence.html.
const slug = (s: string) => s.replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase();

function sourcePages(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === "_site" || name === "node_modules") continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sourcePages(p));
    else if (/\.(html|md)$/.test(name)) out.push(p);
  }
  return out;
}

const includeRe = /\{%\s*include\s+matrix-evidence\.html\s+claim="([^"]*)"/g;
const includeCalls = sourcePages(docs).flatMap((p) =>
  [...readFileSync(p, "utf8").matchAll(includeRe)].map((m) => ({ page: relative(root, p), claim: m[1] })),
);

// The hand-written pages that describe capabilities; none may carry matrix bounds text.
const PROSE_PAGES = [
  "docs/index.html",
  "docs/how-it-works.md",
  "docs/install.md",
  "docs/evidence.html",
  "docs/_includes/platform-evidence.html",
];

describe("site capability limits come from the matrix data", () => {
  it("the site data file is byte-identical to the published matrix twin", () => {
    expect(read("docs/_data/assurance_matrix.json")).toBe(read("docs/assurance-matrix.json"));
  });

  it("every matrix row has non-empty bounds and a unique anchor", () => {
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) expect(row.bounds.trim(), row.claim).not.toBe("");
    const anchors = rows.map((row) => slug(row.claim));
    expect(new Set(anchors).size).toBe(anchors.length);
  });

  it("every evidence include names exactly one matrix row, and the home page and how-it-works use it", () => {
    expect(includeCalls.some((c) => c.page === "docs/index.html")).toBe(true);
    expect(includeCalls.some((c) => c.page === "docs/how-it-works.md")).toBe(true);
    for (const { page, claim } of includeCalls) {
      expect(rows.filter((row) => row.claim === claim).length, `${page}: ${claim}`).toBe(1);
    }
  });

  it("the Limits page renders each row's bounds escaped and verbatim, under the include's anchor", () => {
    const limits = read("docs/limits.html");
    const include = read("docs/_includes/matrix-evidence.html");
    expect(limits).toContain("{% for row in matrix_rows %}{% assign row_id = row.claim | slugify %}");
    expect(limits).toContain('id="{{ row_id }}"');
    expect(limits).toContain('<dd class="matrix-bounds">{{ row.bounds | escape }}</dd>');
    expect(include).toContain("#{{ matrix_row.claim | slugify }}");
    expect(include).toContain("{{ matrix_row.status | escape }}");
    expect(include).toContain("MATRIX ROW MISSING");
  });

  it("no page links into /limits/ by hand; every Limits link comes from the include", () => {
    for (const p of sourcePages(docs)) {
      const rel = relative(root, p);
      if (rel === "docs/_includes/matrix-evidence.html") continue;
      expect(readFileSync(p, "utf8"), rel).not.toMatch(/\/limits\/#/);
    }
  });

  it("no matrix bounds sentence is copied into a hand-written capability page", () => {
    // 40 characters is long enough that a match is a copied clause, not a shared
    // phrase such as a platform name; whole-cell copies are caught as well.
    const MIN_COPIED_CLAUSE = 40;
    const sentences = rows.flatMap((row) =>
      [row.bounds, ...row.bounds.split(/(?<=[.;:])\s+/)].filter((s) => s.length >= MIN_COPIED_CLAUSE),
    );
    for (const page of PROSE_PAGES) {
      const text = read(page);
      for (const sentence of sentences) expect(text.includes(sentence), `${page} copies: ${sentence}`).toBe(false);
    }
  });
});
