/**
 * THE STRUCTURAL GUARD for the claim register (fix-round 3, 2026-07-19).
 *
 * `claim-basis.ts` explains why this exists: this subsystem produced the same
 * "success derived from control flow, not from an observation" defect four
 * times across three gate rounds, at four different altitudes. Fixing the
 * named site each round is what produced round four. This test makes a NEW
 * unclassified claim visible without a reviewer having to notice it.
 *
 * WHAT IS A COMPILE ERROR vs A FAILING TEST -- stated honestly, because the
 * difference matters and it would be easy to overclaim here:
 *
 *   - COMPILE ERROR: `CLAIM_SITES` is a total `Record<ClaimSiteId, ...>`. Add
 *     an id to the union without a row and `tsc` refuses. (Same shape as
 *     `ARTIFACT_SCOPES` in evidence-pack.)
 *   - FAILING TEST (this file): a claim-shaped literal appearing in either
 *     directory without a matching registry update. This is a ratchet on the
 *     literal COUNT per file, so it catches additions, not just new files.
 *   - NEITHER: a claim in a shape the detector cannot see -- most importantly
 *     a `Promise<void>` whose contract is "this resolving means state X holds",
 *     which is the exact shape of the round-4 blocker. Those rows carry
 *     `detectorBlind: true` and are maintained by review. The guard reduces the
 *     surface a reviewer must hold; it does not eliminate it.
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";

import {
  CLAIM_LITERAL_COUNTS,
  CLAIM_SITES,
  claimLiteralRegex,
  type ClaimSiteDeclaration,
  type ClaimSiteId,
} from "../../src/egress-gate/claim-basis.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function readSource(repoRelative: string): string {
  return readFileSync(join(REPO_ROOT, repoRelative), "utf8");
}

function countClaimLiterals(source: string): number {
  const re = claimLiteralRegex();
  let n = 0;
  for (const line of source.split("\n")) {
    const matched = line.match(re);
    if (matched !== null) n += matched.length;
  }
  return n;
}

const entries = Object.entries(CLAIM_SITES) as Array<[ClaimSiteId, ClaimSiteDeclaration]>;

describe("claim register: every claim is observed, weakened, or documented", () => {
  it("declares a non-empty claim and a real source symbol for every site", () => {
    const missing: string[] = [];
    for (const [id, site] of entries) {
      expect(site.claim.length, `${id} has an empty claim`).toBeGreaterThan(0);
      const source = readSource(site.file);
      if (!source.includes(site.symbol)) missing.push(`${id} -> ${site.file}#${site.symbol}`);
    }
    // A renamed or deleted symbol rots the register silently otherwise.
    expect(missing, "registry rows naming symbols that no longer exist").toEqual([]);
  });

  it("requires `unobserved` on every documented-bound and weakened row, and forbids it on observed rows", () => {
    const offenders: string[] = [];
    for (const [id, site] of entries) {
      const hasBound = site.unobserved !== undefined && site.unobserved.trim().length > 0;
      if (site.basis === "observed" && hasBound) {
        offenders.push(`${id}: observed rows must not carry an unobserved note`);
      }
      if (site.basis !== "observed" && !hasBound) {
        // THE RULE: silence is not an option. A control-flow-derived claim
        // that does not name what it failed to observe is a defect.
        offenders.push(`${id}: ${site.basis} rows must name what is NOT observed`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("keeps the round-3 fixes classified as observed (a regression here means a claim went back to intent)", () => {
    // These four are the sites the three gate rounds actually broke on. If a
    // future change downgrades one, this test names it rather than leaving it
    // to a fifth review round.
    const mustBeObserved: ClaimSiteId[] = [
      "release-barrier.reassert-parked-stopped",
      "release-barrier.revert-harness-restarted",
      "release-barrier.revert-plist-restored",
      "harness-daemon.set-job-disabled",
      "harness-daemon.uninstall-stopped",
      "harness-daemon.install-reload",
      "release-barrier.park-cleanup-job-disabled",
      "arming-wiring.barrier-remove-hold",
    ];
    for (const id of mustBeObserved) {
      expect(CLAIM_SITES[id].basis, `${id} must stay observed`).toBe("observed");
    }
  });
});

describe("claim register: the literal ratchet", () => {
  it("matches the recorded per-file claim-literal counts", () => {
    const drift: string[] = [];
    for (const [file, expected] of Object.entries(CLAIM_LITERAL_COUNTS)) {
      const actual = countClaimLiterals(readSource(file));
      if (actual !== expected) {
        drift.push(`${file}: recorded ${expected}, found ${actual}`);
      }
    }
    // If this fails you have added (or removed) a claim-shaped literal in the
    // exclusive-egress subsystem. That is not a reason to bump the number: go
    // to `src/egress-gate/claim-basis.ts`, decide whether the new claim is
    // OBSERVED, WEAKENED, or a DOCUMENTED BOUND, add its row, and update the
    // count in the same commit. The number is the forcing function, not the
    // requirement.
    expect(drift, "claim-literal drift -- classify the new claim in claim-basis.ts").toEqual([]);
  });

  it("does not silently lose a tracked file", () => {
    for (const file of Object.keys(CLAIM_LITERAL_COUNTS)) {
      expect(() => readSource(file), `${file} is tracked but unreadable`).not.toThrow();
    }
  });

  it("states its own bound: detector-blind rows exist and are declared, not hidden", () => {
    const blind = entries.filter(([, site]) => site.detectorBlind === true);
    // The guard's honesty check. If this ever reaches zero, someone has
    // quietly deleted the acknowledgement that `Promise<void>` claims -- the
    // shape of the round-4 blocker -- are not machine-detected.
    expect(blind.length).toBeGreaterThan(0);
  });
});
