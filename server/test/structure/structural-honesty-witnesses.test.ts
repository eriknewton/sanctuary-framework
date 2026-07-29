import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { STRUCTURAL_HONESTY_CLAIM_IDS } from "../../src/claim-witness.js";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");
const CLAIM_WITNESS = "server/src/claim-witness.ts";
const CLAIM_BASIS = "server/src/egress-gate/claim-basis.ts";

function readSource(repoRelative: string): string {
  return readFileSync(join(REPO_ROOT, repoRelative), "utf8");
}

function tsFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return tsFiles(full);
    return entry.isFile() && entry.name.endsWith(".ts") ? [full] : [];
  });
}

function repoRelative(full: string): string {
  return relative(REPO_ROOT, full).split("/").join("/");
}

function linesContaining(source: string, needle: string): string[] {
  return source
    .split("\n")
    .map((line, index) => ({ line, index: index + 1 }))
    .filter(({ line }) => line.includes(needle))
    .map(({ line, index }) => `${index}: ${line.trim()}`);
}

function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function witnessCallRegex(helper: "observing" | "verifiedEmptyFrom", id: string): RegExp {
  return new RegExp(`${helper}\\(\\s*${escapeRegExp(JSON.stringify(id))}`);
}

function occurrenceIndexes(source: string, needle: string): number[] {
  const indexes: number[] = [];
  let index = source.indexOf(needle);
  while (index !== -1) {
    indexes.push(index);
    index = source.indexOf(needle, index + needle.length);
  }
  return indexes;
}

function isWitnessedOccurrence(source: string, index: number): boolean {
  const before = source.slice(Math.max(0, index - 120), index);
  return /(?:observing|verifiedEmptyFrom)\(\s*$/.test(before);
}

describe("structural honesty witnesses", () => {
  it("keeps Observed and VerifiedEmpty brands minted only by the witness module", () => {
    const offenders: string[] = [];
    for (const full of tsFiles(SERVER_SRC)) {
      const rel = repoRelative(full);
      if (rel === CLAIM_WITNESS) continue;
      const source = readFileSync(full, "utf8");
      if (/\bas\s+(?:Observed|VerifiedEmpty)\b/.test(source)) {
        offenders.push(rel);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("routes every structural-honesty claim id through its witness constructor", () => {
    const srcFiles = tsFiles(SERVER_SRC)
      .map((full) => ({ rel: repoRelative(full), source: readFileSync(full, "utf8") }))
      .filter(({ rel }) => rel !== CLAIM_WITNESS && rel !== CLAIM_BASIS);
    const missing: string[] = [];
    const stray: string[] = [];

    for (const id of STRUCTURAL_HONESTY_CLAIM_IDS) {
      const helper = id === "evidence-pack.inventory.empty-verified"
        ? "verifiedEmptyFrom"
        : "observing";
      const reachable = srcFiles.some(({ source }) =>
        witnessCallRegex(helper, id).test(source),
      );
      if (!reachable) missing.push(`${id} via ${helper}`);

      for (const { rel, source } of srcFiles) {
        for (const index of occurrenceIndexes(source, `"${id}"`)) {
          if (isWitnessedOccurrence(source, index)) {
            continue;
          }
          stray.push(`${rel}:${linesContaining(source, `"${id}"`).join(", ")}`);
        }
      }
    }

    expect(missing).toEqual([]);
    expect(stray).toEqual([]);
  });

  it("blocks raw auto-provision and castle-wall definitive outcome claims", () => {
    const orchestrate = readSource("server/src/castle-wall/provision/orchestrate.ts");
    const exclusiveArm = readSource("server/src/castle-wall/provision/exclusive-arm.ts");

    expect(orchestrate).toContain(`observing("provision-orchestrate.armed"`);
    expect(orchestrate).toContain(`observing("provision-orchestrate.disarmed"`);
    expect(orchestrate).not.toMatch(/disarmObservedOff\s*:\s*(?:true|disarmObservedOff\s*\?\s*true)/);
    expect(orchestrate).not.toContain(`return { kind: "armed", uid }`);

    expect(exclusiveArm).toMatch(
      witnessCallRegex("observing", "provision-exclusive-arm.exclusive-armed"),
    );
    expect(exclusiveArm).toMatch(
      witnessCallRegex("observing", "provision-exclusive-arm.coarse-composition-restored"),
    );
    expect(exclusiveArm).not.toMatch(/coarseCompositionRestored\s*=\s*true/);
    expect(exclusiveArm).not.toMatch(/coarseCompositionRestored\s*:\s*true/);
  });

  it("requires a verified-empty witness for scoped definitive-none render paths", () => {
    const observe = readSource("server/src/cli/castle-wall-observe.ts");
    const inventory = readSource("server/src/evidence-pack/inventory.ts");

    const noCandidatesIndex = observe.indexOf(`"No candidates. Turn on observe mode`);
    const noCandidatesGateIndex = observe.lastIndexOf("claimFromVerifiedEmpty(", noCandidatesIndex);
    expect(noCandidatesIndex).toBeGreaterThanOrEqual(0);
    expect(noCandidatesGateIndex).toBeGreaterThanOrEqual(0);
    expect(noCandidatesIndex - noCandidatesGateIndex).toBeLessThan(200);
    expect(observe).toContain("Pending candidates: ${formatPendingCandidateCount(census)}");

    expect(inventory).toContain(`verifiedEmptyFrom("evidence-pack.inventory.empty-verified"`);
    expect(inventory).toContain("claimFromVerifiedEmpty(witness, emptyVerified())");
    expect(inventory).not.toMatch(/return\s+emptyVerified\(\);/);
    expect(inventory).not.toMatch(/:\s*emptyVerified\(\)/);
  });
});
