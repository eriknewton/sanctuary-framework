/**
 * `docs/llms-full.txt` is served at https://sanctuaryprotocol.ai/llms-full.txt
 * for agents deciding whether and how to install Sanctuary. It promises that
 * nothing in it says more than README.md; this test is what makes that
 * structural. Every line after the provenance comment must be a whole README
 * line, in README order, and a section the copy includes is included whole,
 * once the absolute repository links the copy adds are turned back into the
 * README's relative links. A sentence edited in one file and not the other
 * fails here, on every commit, instead of drifting into a public overclaim or
 * a stale bound.
 *
 * Must match the link rewrite used to build docs/llms-full.txt: relative
 * README links become https://github.com/eriknewton/sanctuary-framework/blob/main/<path>
 * (or /tree/main/ for directories), and a README-internal anchor becomes
 * README.md#<anchor> on that base.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const REPO_ROOT = new URL("../../../", import.meta.url);
const README = readFileSync(fileURLToPath(new URL("README.md", REPO_ROOT)), "utf8");
const LLMS_FULL = readFileSync(fileURLToPath(new URL("docs/llms-full.txt", REPO_ROOT)), "utf8");

const ABSOLUTE_REPO_LINK = /https:\/\/github\.com\/eriknewton\/sanctuary-framework\/(?:blob|tree)\/main\//g;

function toReadmeForm(line: string): string {
  return line.replace(ABSOLUTE_REPO_LINK, "").replace(/\(README\.md#/g, "(#");
}

function isHeading(line: string): boolean {
  return /^#{1,6} /.test(line);
}

describe("llms-full.txt is copied from the README", () => {
  it("every line after the provenance comment is a whole README line, in README order, with whole sections only omitted", () => {
    const readmeLines = README.split("\n");
    const lines = LLMS_FULL.split("\n");
    const provenance = lines.findIndex((l) => l.startsWith("<!-- Generated"));
    expect(provenance, "the provenance comment must be present").toBeGreaterThanOrEqual(0);
    // Whole-line equality (not substring) rejects a truncated fragment; the
    // strictly increasing README index rejects reordering. Blank lines are
    // skipped because section breaks in the copy are not README content.
    const notCopied: string[] = [];
    const partialOmissions: string[] = [];
    const copiedAt: number[] = [];
    let previous = -1;
    lines.slice(provenance + 1).forEach((line, i) => {
      if (line.trim() === "") return;
      const readmeForm = toReadmeForm(line);
      const at = readmeLines.findIndex(
        (r, j) => j > previous && (r === line || r === readmeForm),
      );
      if (at === -1) notCopied.push(`${provenance + 2 + i}: ${line.slice(0, 120)}`);
      else {
        copiedAt.push(at);
        previous = at;
      }
    });
    expect(notCopied, "a line in docs/llms-full.txt is not a whole README line in README order; edit README.md first, then copy").toEqual([]);

    // Omission check: the copy may leave out whole README sections (the run
    // from one heading up to the next heading), never part of one. A gap of
    // skipped non-blank README lines must therefore start at a heading, and
    // the copy must resume at a heading (or at the end of the README). The
    // README text before the first copied line (title, badges) is exempt.
    const nonBlankBetween = (from: number, to: number): number[] => {
      const out: number[] = [];
      // A horizontal rule ("---") is a README section separator, not content.
      for (let k = from; k < to; k++) {
        const t = readmeLines[k].trim();
        if (t !== "" && t !== "---") out.push(k);
      }
      return out;
    };
    for (let c = 0; c < copiedAt.length; c++) {
      const from = copiedAt[c] + 1;
      const resumeAt = c + 1 < copiedAt.length ? copiedAt[c + 1] : readmeLines.length;
      const skipped = nonBlankBetween(from, resumeAt);
      if (skipped.length === 0) continue;
      const resumesAtSectionStart = resumeAt === readmeLines.length || isHeading(readmeLines[resumeAt]);
      if (!isHeading(readmeLines[skipped[0]]) || !resumesAtSectionStart) {
        partialOmissions.push(`README ${skipped[0] + 1}: ${readmeLines[skipped[0]].slice(0, 120)}`);
      }
    }
    expect(partialOmissions, "docs/llms-full.txt leaves out part of a README section; copy the whole section or leave the whole section out").toEqual([]);
  });
});
