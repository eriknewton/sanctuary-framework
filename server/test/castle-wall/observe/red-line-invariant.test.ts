/**
 * Castle Wall Observe / Learn Allow-List v1 -- THE RED-LINE INVARIANT.
 *
 * CI DoD test 3 (the load-bearing test, per the decision brief and the
 * adversarial review's finding H1): an observed-but-not-yet-approved
 * destination is still blocked, AND the live rules are byte-unchanged,
 * until explicit approval. Observing must never become allowing.
 *
 * This test asserts BOTH halves:
 *   (a) the egress evaluator (`decideEgressProxyConnect`, the exact function
 *       the daemon/in-process proxy calls on every CONNECT) still denies a
 *       destination that has been recorded as a candidate but not promoted;
 *   (b) `promoteCandidates` never calls its injected `publish` (the only
 *       function that can mutate the live ruleset) when approval is denied
 *       or unavailable -- proven with a `publish` spy that THROWS if it is
 *       ever invoked on the denied path.
 *
 * A structural assertion pins the invariant at the module-boundary level
 * too: nothing under `castle-wall/observe/` imports the enforcing evaluator
 * module, and the evaluator module imports nothing from
 * `castle-wall/observe/` -- so there is no code path, today or by an
 * accidental future edit inside these files, for the evaluator to consult
 * the candidate store.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { decideEgressProxyConnect } from "../../../src/castle-wall/egress-proxy.js";
import { foldObservations } from "../../../src/castle-wall/observe/fold.js";
import { promoteCandidates } from "../../../src/castle-wall/observe/promote.js";
import { candidateKey, type FlowObservationEvent } from "../../../src/castle-wall/observe/types.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "src");

const NOVEL_AUTHORITY = "new-tool.example.com:443";

const DENIED_FLOW: FlowObservationEvent = {
  timestamp: "2026-07-07T10:00:00.000Z",
  agent: { id: "agent-1", template: "claude-code" },
  destination: { host: "new-tool.example.com", ip: "203.0.113.9", port: 443, protocol: "tcp" },
  hostname_source: "sni",
  disposition: "denied",
};

describe("THE RED-LINE INVARIANT: observing never becomes allowing", () => {
  it("a recorded-but-unpromoted destination is still denied by decideEgressProxyConnect, and the ruleset used is byte-unchanged", async () => {
    const liveRulesBefore: AllowlistRule[] = [];

    // Step 1: the wall denies the novel destination (this is what triggers
    // observe mode to record it in the first place).
    const firstDecision = await decideEgressProxyConnect(NOVEL_AUTHORITY, { rules: liveRulesBefore });
    expect(firstDecision).toEqual({ disposition: "deny", reason: "allowlist_miss" });

    // Step 2: observe mode folds the denial into a candidate. This is a
    // read/write against the SEPARATE candidate store only; it takes no
    // rules array and returns no rules array -- it cannot touch enforcement.
    const candidates = foldObservations([DENIED_FLOW]);
    expect(candidates).toHaveLength(1);

    // Step 3: WITHOUT promoting, decide the SAME authority against the SAME
    // rules array again. It is still denied, and the array is the identical
    // reference/contents -- nothing observed it and nothing mutated it.
    const secondDecision = await decideEgressProxyConnect(NOVEL_AUTHORITY, { rules: liveRulesBefore });
    expect(secondDecision).toEqual({ disposition: "deny", reason: "allowlist_miss" });
    expect(liveRulesBefore).toEqual([]);
  });

  it("promoteCandidates NEVER calls publish (the only manifest-mutating step) when approval is denied", async () => {
    const candidates = foldObservations([DENIED_FLOW]);
    const candidatesByKey = new Map(candidates.map((c) => [candidateKey(c), c]));
    const [key] = [...candidatesByKey.keys()];

    const publishSpy = throwingPublish();

    const outcome = await promoteCandidates(
      [{ key: key! }],
      candidatesByKey,
      {
        readVerifiedManifest: async () => ({ status: "ok", rules: [], digest: "digest-empty" }),
        approve: async () => ({ allowed: false, reason: "operator declined" }),
        publish: publishSpy,
        now: new Date("2026-07-07T12:00:00.000Z"),
      },
    );

    expect(outcome.status).toBe("denied");

    // Re-decide: the destination is STILL denied because publish() was never
    // called, so the live rules (an empty array here, standing in for "the
    // manifest on disk") are exactly as they were.
    const decision = await decideEgressProxyConnect(NOVEL_AUTHORITY, { rules: [] });
    expect(decision).toEqual({ disposition: "deny", reason: "allowlist_miss" });
  });

  it("promoteCandidates never calls approve() at all when there is nothing valid to promote (no candidates to approve)", async () => {
    let approveCalled = false;
    const outcome = await promoteCandidates(
      [{ key: "does-not-exist" }],
      new Map(),
      {
        readVerifiedManifest: async () => ({ status: "ok", rules: [], digest: "digest-empty" }),
        approve: async () => {
          approveCalled = true;
          return { allowed: true };
        },
        publish: throwingPublish(),
        now: new Date("2026-07-07T12:00:00.000Z"),
      },
    );
    expect(outcome.status).toBe("no_candidates");
    expect(approveCalled).toBe(false);
  });

  it("STRUCTURAL PIN: no file under castle-wall/observe/ imports the enforcing evaluator module, and the evaluator imports nothing from castle-wall/observe/", () => {
    // Match actual import/export statements only (`from "...egress-proxy..."`),
    // not mere textual mentions in doc comments (this module's own header
    // documentation legitimately NAMES egress-proxy.ts as the evaluator it
    // must never be imported by).
    const importsModuleNamed = (source: string, needle: string): boolean =>
      /(?:import|export)[^;]*from\s+["'][^"']*/.test(source) &&
      new RegExp(`(?:import|export)[^;]*from\\s+["'][^"']*${needle}[^"']*["']`).test(source);

    const observeDir = join(SRC, "castle-wall", "observe");
    const observeFiles = readdirSync(observeDir).filter((f) => f.endsWith(".ts"));
    expect(observeFiles.length).toBeGreaterThan(0);

    for (const file of observeFiles) {
      const source = readFileSync(join(observeDir, file), "utf8");
      expect(
        importsModuleNamed(source, "egress-proxy"),
        `${file} must never import the enforcing evaluator module (egress-proxy.ts)`,
      ).toBe(false);
    }

    const evaluatorSource = readFileSync(join(SRC, "castle-wall", "egress-proxy.ts"), "utf8");
    expect(
      importsModuleNamed(evaluatorSource, "observe/"),
      "egress-proxy.ts must never import anything from castle-wall/observe/ (the enforcing evaluator must never consult the candidate store)",
    ).toBe(false);
  });
});

/** A publish() double that throws if invoked -- used to prove a code path never calls it. */
function throwingPublish(): (rules: AllowlistRule[]) => Promise<{ written_rule_filenames: string[]; removed_rule_filenames: string[] }> {
  return async () => {
    throw new Error("THE RED-LINE INVARIANT VIOLATED: publish() was called without an approved promote.");
  };
}
