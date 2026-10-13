/**
 * `docs/llms-full.txt` is served at https://sanctuaryprotocol.ai/llms-full.txt
 * for agents deciding whether and how to install Sanctuary. It promises that
 * nothing in it says more than README.md; this test is what makes that
 * structural. Every line after the provenance comment must be README text once
 * the absolute repository links the copy adds are turned back into the
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

describe("llms-full.txt is copied from the README", () => {
  it("every line after the provenance comment is README text", () => {
    const lines = LLMS_FULL.split("\n");
    const provenance = lines.findIndex((l) => l.startsWith("<!-- Generated"));
    expect(provenance, "the provenance comment must be present").toBeGreaterThanOrEqual(0);
    const notInReadme = lines
      .slice(provenance + 1)
      .map((line, i) => ({ n: provenance + 2 + i, line }))
      .filter(({ line }) => line.trim() !== "")
      .filter(({ line }) => !README.includes(line) && !README.includes(toReadmeForm(line)))
      .map(({ n, line }) => `${n}: ${line.slice(0, 120)}`);
    expect(notInReadme, "a line in docs/llms-full.txt is not README text; edit README.md first, then copy").toEqual([]);
  });
});
