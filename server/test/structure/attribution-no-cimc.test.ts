/**
 * ATTRIBUTION guard (DoE review C-1, the no-CIMC rule).
 *
 * THE RULE (CLAUDE.md, MANDATORY): "No public-facing document, README, blog
 * post, plugin manifest, package metadata, or software artifact may reference
 * or attribute CIMC as author or creator of Sanctuary or Concordia. Erik
 * Newton is the sole author. CIMC may be mentioned in internal/biographical
 * context only."
 *
 * Until now this was a prose review gate. This test converts it into a
 * CI-failing fact for the PUBLIC-FACING surface, so a stray "CIMC" in a README,
 * changelog entry, doc, package manifest, or user-visible product string fails
 * the build instead of relying on a human to catch it.
 *
 * SCOPE: the shared public-facing surface (see `public-surface.ts`) — public
 * root docs, the public text subtrees, package metadata + the plugin manifest —
 * PLUS every tracked first-party JS/TS source file (firstPartySourceFiles:
 * server/src and the other first-party trees; CIMC is forbidden everywhere,
 * including code comments, because a comment can also attribute authorship)
 * PLUS public example/script code (.py/.sh under the public subtrees,
 * publicExampleCodeFiles). The no-CIMC scope is intentionally BROADER than the
 * no-em-dash scope: a CIMC attribution anywhere in a public/first-party artifact
 * is a hard rule break, whereas em-dashes are a typography rule (see em-dash.test.ts).
 * Deliberately OUT of scope: Archive/ (frozen historical record), CLAUDE.md and
 * other internal briefings (the rule itself permits internal/biographical
 * mention), server/docs/design-refs (internal), and "Sanctuary Site/" (the
 * live marketing site lives in a separate Pages repo and was not enumerated in
 * this gate's scope).
 *
 * ALLOWLIST: a small set of EXISTING, benign occurrences that are NOT
 * attributions — e.g. a changelog line that RECORDS the removal of CIMC
 * attribution ("updated from CIMC to Erik Newton"). These are documented below
 * so the guard fails on any NEW CIMC reference while not flagging the
 * compliance record itself. Adding to this list must be a conscious, reviewed
 * decision; never extend it just to silence a real new attribution.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  REPO_ROOT,
  publicFacingRelPaths,
  firstPartySourceFiles,
  publicExampleCodeFiles,
  firstPartyNonJsSourceFiles,
} from "./public-surface";

/**
 * Case-insensitive token we forbid: the contiguous `CIMC` and the dotted
 * `C.I.M.C.` / `C.I.M.C` rendering (a plausible "formal" form). Arbitrary
 * spaced-out obfuscation (`C I M C`) is intentionally NOT chased — that is
 * deliberate evasion, not an accidental attribution, and broad spacing patterns
 * risk false positives; human review (which these guards augment) is the
 * backstop for adversarial obfuscation.
 */
const FORBIDDEN = /CIMC|C\.I\.M\.C\.?/i;

/**
 * EXISTING benign occurrences, keyed by `<repo-relative-path>::<exact line text
 * trimmed>`. These are meta-references that record compliance with the rule,
 * not attributions. Keep this list minimal.
 */
const ALLOWLIST: ReadonlySet<string> = new Set<string>([
  // CHANGELOG entry recording the historical removal of CIMC attribution
  // (it literally says "updated from CIMC to Erik Newton"). Not an attribution.
  "CHANGELOG.md::- Author attribution updated from CIMC to Erik Newton across all public-facing docs (per mandatory attribution rule)",
]);

/**
 * The full in-scope set (repo-relative paths): the doc/text/metadata public
 * surface PLUS all first-party JS/TS source (server/src and the other
 * first-party trees). CIMC is forbidden in code too — a comment or string in
 * any shipped/first-party source can carry an attribution.
 */
function inScopeRelPaths(): string[] {
  const set = new Set<string>([
    ...publicFacingRelPaths(),
    ...firstPartySourceFiles(),
    ...publicExampleCodeFiles(),
    ...firstPartyNonJsSourceFiles(),
  ]);
  return [...set].sort();
}

describe("attribution guard (no CIMC in public-facing artifacts)", () => {
  it("contains no CIMC reference on any public-facing surface", () => {
    const rels = inScopeRelPaths();
    // sanity: scope resolved to a real, non-trivial file set
    expect(rels.length).toBeGreaterThan(50);

    const hits: string[] = [];
    for (const rel of rels) {
      const lines = readFileSync(join(REPO_ROOT, rel), "utf8").split("\n");
      lines.forEach((line, i) => {
        if (FORBIDDEN.test(line)) {
          const key = `${rel}::${line.trim()}`;
          if (!ALLOWLIST.has(key)) {
            hits.push(`${rel}:${i + 1}: ${line.trim()}`);
          }
        }
      });
    }

    expect(
      hits,
      "Public-facing artifact references CIMC (CLAUDE.md attribution rule: " +
        "Erik Newton is the sole author; CIMC may be mentioned in " +
        "internal/biographical context ONLY). Offending line(s):\n  " +
        hits.join("\n  ") +
        "\n\nFIX: remove the CIMC reference / re-attribute to Erik Newton. If " +
        "this is a genuine benign meta-reference (e.g. a changelog line that " +
        "records removing CIMC attribution), add its exact key to ALLOWLIST in " +
        "this test as a reviewed decision.",
    ).toEqual([]);
  });
});
