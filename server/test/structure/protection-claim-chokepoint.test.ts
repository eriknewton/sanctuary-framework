import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");

const PROTECTION_PROSE = [
  "Your agent is protected.",
  "Your agent is wrapped, but only coarse Castle Wall enforcement is confirmed.",
  "Your agent is wrapped, but enforcement is not confirmed.",
  "Castle Wall Full",
  "Castle Wall coarse-only (fine-grained egress not live)",
  "Castle Wall NOT ARMED (traffic not filtered)",
  "Castle Wall status unknown (not confirmed armed)",
] as const;

const CHOKEPOINT = "server/src/egress-gate/protection-claim.ts";
const FROZEN_DASHBOARD_HERO = "server/src/dashboard/html.ts";

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

function stripComments(source: string): string {
  let out = "";
  let quote: '"' | "'" | "`" | null = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let i = 0; i < source.length; i++) {
    const ch = source[i]!;
    const next = source[i + 1];
    if (lineComment) {
      if (ch === "\n") {
        lineComment = false;
        out += ch;
      }
      continue;
    }
    if (blockComment) {
      if (ch === "*" && next === "/") {
        blockComment = false;
        i++;
      } else if (ch === "\n") {
        out += ch;
      }
      continue;
    }
    if (quote !== null) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "/" && next === "/") {
      lineComment = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      blockComment = true;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
    }
    out += ch;
  }
  return out;
}

function allowedFilesFor(phrase: string): Set<string> {
  const allowed = new Set([CHOKEPOINT]);
  if (phrase === "Your agent is protected.") {
    // Frozen dashboard token: server/reorg-surface-manifest.md protects this
    // exact HERO_COPY string and id="hero-copy"; this task must not change it.
    allowed.add(FROZEN_DASHBOARD_HERO);
  }
  return allowed;
}

describe("protection-state claim chokepoint", () => {
  it("keeps exact protection-state prose in the claim chokepoint", () => {
    // This is deliberately a lexical tripwire, not a proof of totality. It
    // cannot catch template substitution, split lookup tables, or synonyms.
    const violations: string[] = [];
    for (const file of tsFiles(SERVER_SRC)) {
      const rel = relative(REPO_ROOT, file);
      const source = stripComments(readFileSync(file, "utf8"));
      for (const phrase of PROTECTION_PROSE) {
        if (source.includes(phrase) && !allowedFilesFor(phrase).has(rel)) {
          violations.push(`${rel}: ${phrase}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });
});
