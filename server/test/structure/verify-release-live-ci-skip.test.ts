// fail-before-exempt: the gate this checks lives only under server/test (live.test.ts and live-gate.ts), which the fail-before check keeps at HEAD while it reverts server/src, so no server/src revert can make it fail; its fail-before evidence is the run at ca1ceb9d, where the gate check failed because live.test.ts did not gate on CI.
/**
 * The networked verify-release live test is skipped in CI whatever its opt-in
 * variable says. This checks the gate predicate over the environment shapes
 * that matter and that live.test.ts gates on that predicate and nothing else.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LIVE_OPT_IN_VARIABLE, liveTestEnabled } from "../verify-release/live-gate.js";

const LIVE_TEST = join(__dirname, "..", "verify-release", "live.test.ts");

describe("verify-release live test CI skip", () => {
  it.each([
    [{ CI: "true", [LIVE_OPT_IN_VARIABLE]: "1" }, false],
    [{ CI: "1", [LIVE_OPT_IN_VARIABLE]: "1" }, false],
    [{ CI: "", [LIVE_OPT_IN_VARIABLE]: "1" }, false],
    [{ CI: "false", [LIVE_OPT_IN_VARIABLE]: "1" }, false],
    [{ CI: "true" }, false],
    [{ [LIVE_OPT_IN_VARIABLE]: "1" }, true],
    [{ [LIVE_OPT_IN_VARIABLE]: "true" }, false],
    [{}, false],
  ])("env %j enables the live test: %s", (env, enabled) => {
    expect(liveTestEnabled(env)).toBe(enabled);
  });

  it("live.test.ts gates its only describe on liveTestEnabled(process.env), and reads the opt-in nowhere else", () => {
    const source = readFileSync(LIVE_TEST, "utf8");
    expect(source).toMatch(/import \{[^}]*\bliveTestEnabled\b[^}]*\} from "\.\/live-gate\.js";/);
    expect([...source.matchAll(/\bdescribe(\.[a-zA-Z]+)*\(/g)].map(m => m[0])).toEqual(["describe.skipIf("]);
    expect(source).toContain("describe.skipIf(!liveTestEnabled(process.env))(");
    expect(source).not.toMatch(/process\.env\.SANCTUARY_VERIFY_RELEASE_LIVE|process\.env\[/);
  });
});
