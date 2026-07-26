/**
 * Publish-workflow signing gate (structural guard).
 *
 * THE INCIDENT (2026-07-25, v1.7.0 publish, run 30180180024): the publish
 * workflow carried a pre-activation skip path — a step NAMED "Signed manifest
 * skipped (no signing key configured)" that ran only when the
 * RELEASE_SIGNING_KEY secret was empty. After the key was activated
 * (2026-07-01) every healthy run SKIPPED that step, so the run's step list
 * showed a skipped row whose name read as "the signing was skipped". The
 * signing had in fact succeeded; the step NAME was a false defect report,
 * because it asserted a condition ("no signing key configured") that the row's
 * presence did not probe. Same failure shape as the six-week-silent Apple
 * secrets gap: a benign-looking skip standing in front of a configured input.
 *
 * THE POSTURE THIS TEST FREEZES (probe-the-predicate, fail-closed):
 *   1. A fail-closed probe step ("Require release signing key") runs BEFORE
 *      the irreversible `npm publish`, probing the same job-level env the sign
 *      step's key is mapped from, and exits non-zero when it is empty.
 *   2. The sign step is UNCONDITIONAL (no `if:` on the secret) — a missing
 *      key fails the run (the sign script also dies on a missing env var);
 *      there is no skip path in either direction.
 *   3. No step is gated on the secret being empty, and no step NAME asserts a
 *      "skipped"/"skipping" event — a step list must never be able to report
 *      an event that did not happen.
 *
 * ANTI-VACUITY: every negative assertion below is paired with positive
 * assertions from the same parse (the parser must find the real step names and
 * the real secret mappings), so a neutered read of the wrong file cannot pass.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const WORKFLOW_PATH = join(
  REPO_ROOT,
  ".github",
  "workflows",
  "publish-on-tag.yml",
);

const workflow = readFileSync(WORKFLOW_PATH, "utf8");

/** Step names, in file order (the publish workflow is a single job). */
function stepNames(source: string): string[] {
  const names: string[] = [];
  for (const line of source.split("\n")) {
    const m = /^\s*- name:\s*(.+?)\s*$/.exec(line);
    if (m) names.push(m[1]);
  }
  return names;
}

describe("publish workflow: signed-manifest gate is fail-closed and honestly named", () => {
  const names = stepNames(workflow);

  it("parses the real workflow (anti-vacuity: known steps present)", () => {
    // If the parser or path is ever broken, these fail first, so the negative
    // assertions below cannot pass vacuously.
    expect(names.length).toBeGreaterThan(5);
    expect(names).toContain("Publish to npm");
    expect(names).toContain("Sign + attach release manifest");
  });

  it("maps the RELEASE_SIGNING_KEY secret into the job env and the sign step", () => {
    // Job-level mapping (what the probe step reads)...
    expect(workflow).toContain(
      "RELEASE_SIGNING_KEY: ${{ secrets.RELEASE_SIGNING_KEY }}",
    );
    // ...and the sign step consumes the SAME secret under the script's env
    // name. A rename of either side must update this test consciously.
    expect(workflow).toContain(
      "SANCTUARY_RELEASE_SIGNING_KEY_B64URL: ${{ secrets.RELEASE_SIGNING_KEY }}",
    );
  });

  it("probes the signing key and fails closed BEFORE `npm publish`", () => {
    const probeIndex = names.indexOf(
      "Require release signing key (fail closed)",
    );
    const publishIndex = names.indexOf("Publish to npm");
    expect(probeIndex).toBeGreaterThanOrEqual(0);
    expect(publishIndex).toBeGreaterThanOrEqual(0);
    expect(probeIndex).toBeLessThan(publishIndex);

    // The probe must actually test emptiness of the mapped env var and exit
    // non-zero — presence of the step name alone proves nothing.
    expect(workflow).toMatch(
      /if \[\[ -z "\$\{RELEASE_SIGNING_KEY\}" \]\]; then[\s\S]{0,800}?exit 1/,
    );
  });

  it("has NO skip path conditioned on the secret (both directions)", () => {
    // The pre-activation design gated steps on env.RELEASE_SIGNING_KEY
    // emptiness. Post-activation, any such conditional reintroduces a silent
    // green-run path where the manifest quietly stops attaching.
    expect(workflow).not.toContain("env.RELEASE_SIGNING_KEY == ''");
    expect(workflow).not.toContain("env.RELEASE_SIGNING_KEY != ''");
    expect(workflow).not.toMatch(/if:.*RELEASE_SIGNING_KEY/);
  });

  it("has no step NAME asserting a skip event", () => {
    // A step name renders in the run's step list whether the step ran or was
    // skipped. A name that asserts an event ("... skipped ...") therefore
    // reports that event in runs where it did not happen. Names must describe
    // what the step DOES, not what its execution would mean.
    for (const name of names) {
      expect(name.toLowerCase()).not.toContain("skipped");
      expect(name.toLowerCase()).not.toContain("skipping");
    }
  });
});
