/**
 * HKDF label registry reconciliation guard (Phase-0 rename safety net).
 *
 * The single most dangerous trap in the pending l1-l4 -> named-layer rename is a
 * find-replace that touches an HKDF domain-separation LABEL: the label is the
 * info string fed to derivePurposeKey/deriveNamespaceKey/hkdf(), so changing one
 * byte changes the derived key and SILENTLY makes every store encrypted under
 * the old label undecryptable. Fresh-install tests still pass; existing fortress
 * data is lost. (Codebase_Professionalization_Scoping_2026-06-14.md §7, risk 2.)
 *
 * docs/hkdf-info-string-registry.md is a useful index but is NOT the authority —
 * a 2026-06-16 code scan found 35 in-code labels absent from it. The AUTHORITY is
 * this scan. This test:
 *
 *   1. Mechanically scans server/src for every domain-separation label passed to
 *      derivePurposeKey / deriveNamespaceKey / a direct hkdf() call, plus the
 *      named *_PURPOSE / *_HKDF_INFO / HKDF_INFO / HKDF_DOMAIN constants those
 *      call sites reference (resolved to their literal value).
 *   2. Asserts EVERY scanned label appears in the committed classification
 *      artifact (fixtures/at-rest/hkdf-label-classification.json) — so a new
 *      label cannot be added without a classification row.
 *   3. Asserts every classified label still occurs verbatim in server/src — so a
 *      rename that drops a label is caught here (complementing the
 *      frozen-surfaces guard, which lists the byte-frozen subset by hand).
 *   4. Asserts every classification entry is documented in the registry md OR
 *      explicitly marked scan-reconciled, keeping the doc honest.
 *
 * This is a structural reconciliation guard, not a fixture. The decrypt fixtures
 * (at-rest-decrypt-fixtures.test.ts) prove the byte-level round-trip for the
 * decryptable stores; this proves the LABEL INVENTORY is complete and stable.
 *
 * If the scan finds a label not in the classification, the fix is to add a row
 * to hkdf-label-classification.json (and a registry-md row), in the same PR, as
 * a reviewed decision — NEVER to silence the scan.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(import.meta.url);
const SERVER_DIR = join(HERE, "..", "..", "..");
const SERVER_SRC = join(SERVER_DIR, "src");
const CLASSIFICATION_PATH = join(
  SERVER_DIR,
  "test",
  "fixtures",
  "at-rest",
  "hkdf-label-classification.json",
);

interface LabelEntry {
  label: string;
  class:
    | "decryptable-store"
    | "non-decrypt-label"
    | "crypto-domain-label"
    | "wire-constant"
    | "cross-language-fixture";
  owner: string;
  fixture: boolean;
  fixture_via?: string;
  note?: string;
}

interface Classification {
  labels: LabelEntry[];
}

/** All .ts source under server/src, read once into a name->contents map. */
function readSrcFiles(): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".ts")) {
        out.set(full, readFileSync(full, "utf-8"));
      }
    }
  };
  walk(SERVER_SRC);
  return out;
}

const STRING_LITERAL = `["'\`]([^"'\`]+)["'\`]`;

/**
 * Pull every domain-separation label out of the source corpus. Two passes:
 *
 *   (a) Direct string literals passed as the 2nd arg to derivePurposeKey/
 *       deriveNamespaceKey, e.g. derivePurposeKey(master, "l2-context-gate").
 *   (b) Direct string-literal info args to hkdf(...) (4th positional arg) and
 *       new TextEncoder().encode("...") wrapping a label, plus the named
 *       constants (HKDF_INFO / HKDF_DOMAIN / *_HKDF_INFO / *_PURPOSE /
 *       *_HKDF_SALT-excluded) resolved to their literal definition.
 *
 * The goal is completeness for the rename-safety inventory, so the scan favors
 * over-collection (a few extra true labels) over missing one. It deliberately
 * EXCLUDES salts (sanctuary-purpose-v1 / sanctuary-namespace-v1 / the custody
 * salt) since those are the fixed domain separators documented in §A/§D, not
 * per-store labels — but the custody/boot direct-hkdf info args ARE collected.
 */
function scanLabels(files: Map<string, string>): Set<string> {
  const labels = new Set<string>();

  // (a) literal args to the two high-level helpers.
  const helperLiteral = new RegExp(
    `\\b(?:derivePurposeKey|deriveNamespaceKey)\\s*\\(\\s*[^,]+,\\s*${STRING_LITERAL}`,
    "g",
  );
  // (b) named constant -> literal definitions for the constants helper call
  // sites reference. We resolve them globally: any `const NAME = "literal"`
  // whose NAME matches the HKDF-ish suffix set.
  const constLiteral = new RegExp(
    `\\b(?:export\\s+)?const\\s+([A-Z0-9_]*(?:HKDF_INFO|HKDF_DOMAIN|PURPOSE_KEY|_PURPOSE|HKDF_INFO_PREFIX|SIGNING_INFO|AUDIT_INFO))\\s*=\\s*${STRING_LITERAL}`,
    "g",
  );
  // (c) `new TextEncoder().encode("label")` (key-17 signer info args).
  const textEncoder = new RegExp(
    `new\\s+TextEncoder\\(\\)\\.encode\\(\\s*${STRING_LITERAL}\\s*\\)`,
    "g",
  );
  // (d) direct hkdf(...) with an inline stringToBytes("info") / "info" 4th arg.
  const hkdfStringToBytes = new RegExp(
    `\\bhkdf\\([^)]*stringToBytes\\(\\s*${STRING_LITERAL}`,
    "g",
  );

  // Excluded fixed salts / domains that are NOT per-store labels.
  const EXCLUDE = new Set<string>([
    "sanctuary-purpose-v1",
    "sanctuary-namespace-v1",
    "sanctuary-custody-v1",
  ]);

  // A captured value is a real per-store label only if it is a static
  // domain-separation token: kebab/colon/dot form, no template-literal
  // interpolation (`${...}`), no escape sequences (`\n`, `\x..`), no spaces.
  // This rejects the dynamic MAC-domain template strings (e.g.
  // `${ANCHOR_COMMITMENT_DOMAIN}\n...`) and the Ethereum signed-message prefix,
  // which are constructed at runtime and are NOT static HKDF labels.
  const looksLikeLabel = (s: string): boolean =>
    /^[a-z0-9][a-z0-9.:-]*[a-z0-9]$/.test(s) && s.length >= 4 && /[-:.]/.test(s);

  const accept = (v: string): void => {
    if (EXCLUDE.has(v)) return;
    if (v.includes("${") || v.includes("\\")) return; // dynamic / escaped
    if (looksLikeLabel(v)) labels.add(v);
  };

  for (const src of files.values()) {
    for (const re of [helperLiteral, textEncoder, hkdfStringToBytes]) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(src)) !== null) accept(m[1]!);
    }
    constLiteral.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = constLiteral.exec(src)) !== null) accept(m[2]!);
  }

  return labels;
}

describe("HKDF label registry reconciliation", () => {
  const files = readSrcFiles();
  const classification = JSON.parse(
    readFileSync(CLASSIFICATION_PATH, "utf-8"),
  ) as Classification;
  const classified = new Set(classification.labels.map((l) => l.label));
  const scanned = scanLabels(files);

  it("sanity: the scan and the classification both found a meaningful set", () => {
    expect(scanned.size).toBeGreaterThan(40);
    expect(classified.size).toBeGreaterThan(60);
  });

  it("every label found by the code scan is in the committed classification", () => {
    const missing = [...scanned].filter((l) => !classified.has(l)).sort();
    expect(
      missing,
      "In-code HKDF/domain-separation label(s) are NOT in " +
        "fixtures/at-rest/hkdf-label-classification.json. A new label was added " +
        "without a classification row. Add the row (and a registry-md row) in " +
        "THIS PR as a reviewed decision — do not silence the scan. Missing:\n  " +
        missing.join("\n  "),
    ).toEqual([]);
  });

  it("every classified label still occurs verbatim somewhere in server/src", () => {
    const corpus = [...files.values()].join("\n");
    const vanished = classification.labels
      .map((l) => l.label)
      .filter((label) => !corpus.includes(label))
      .sort();
    expect(
      vanished,
      "Classified HKDF label(s) no longer occur in server/src — a rename/reorg " +
        "may have changed a crypto domain-separation label, which would SILENTLY " +
        "break decryption of existing at-rest data. If a label was intentionally " +
        "removed (a deliberate crypto migration), update the classification + " +
        "registry in this same PR. Vanished:\n  " + vanished.join("\n  "),
    ).toEqual([]);
  });

  it("every classification entry declares a valid class", () => {
    const valid = new Set([
      "decryptable-store",
      "non-decrypt-label",
      "crypto-domain-label",
      "wire-constant",
      "cross-language-fixture",
    ]);
    const bad = classification.labels
      .filter((l) => !valid.has(l.class))
      .map((l) => `${l.label} -> ${l.class}`);
    expect(bad, `invalid class on: ${bad.join(", ")}`).toEqual([]);
  });

  it("the registry doc documents (or marks scan-reconciled) every classified label", () => {
    const registryMd = readFileSync(
      join(SERVER_DIR, "docs", "hkdf-info-string-registry.md"),
      "utf-8",
    );
    const undocumented = classification.labels
      .map((l) => l.label)
      .filter((label) => !registryMd.includes(label))
      .sort();
    expect(
      undocumented,
      "Classified label(s) are absent from docs/hkdf-info-string-registry.md. " +
        "The doc must carry a row for every in-code label (the scan is " +
        "authoritative, but the doc must stay reconciled). Add rows for:\n  " +
        undocumented.join("\n  "),
    ).toEqual([]);
  });
});
