// fail-before-exempt: canary window boundary already enforced by the shipped evaluator
/**
 * The canary window boundary in the shared evaluator: a drop exactly
 * CANARY_WINDOW old is accepted and one millisecond older is refused, and a
 * window shorter than the canary period would fail the canary schedule.
 * This file imports no observer module: it pins the evaluator alone.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CANARY_PERIOD, SECOND, canaryWindow } from "../../../src/castle-wall/liveness/constants.js";
import { evaluateLiveness, type LivenessEnvelope, type LivenessInput } from "../../../src/castle-wall/liveness/evaluate.js";

const STATES = JSON.parse(readFileSync(join(__dirname, "fixtures", "states.json"), "utf8")) as { base: LivenessInput & { nowMs: number } };
const BASE = STATES.base as unknown as { nowMs: number; config: { value: { launchd_leeway_s: number } } };
const LEEWAY_MS = BASE.config.value.launchd_leeway_s * SECOND;
const WINDOW = canaryWindow(LEEWAY_MS);
/** The window an older design recorded the canary under, kept here only as the shorter value that must fail. */
const SHORT_RECORDING_WINDOW = 60 * SECOND;

/** The base fixture with the latest confirmed drop captured `ageMs` before the reader's clock. */
function withCanaryAge(ageMs: number): LivenessEnvelope {
  const input = structuredClone(STATES.base) as unknown as Record<string, any>;
  const confirmation = input.daemon.value.raw.canary.last_confirmation;
  confirmation.captured_at_ms = BASE.nowMs - ageMs;
  confirmation.confirmed_at_ms = Math.min(BASE.nowMs, confirmation.captured_at_ms + SECOND);
  return evaluateLiveness(input as LivenessInput);
}

describe("canary window boundary", () => {
  it("accepts a drop exactly CANARY_WINDOW old and refuses one 1 ms older", () => {
    const edge = withCanaryAge(WINDOW);
    expect(edge.wall.state.startsWith("wall_OK_"), edge.wall.reasons.join(",")).toBe(true);
    expect(edge.wall.evidence.canary_age_ms).toBe(WINDOW);
    const older = withCanaryAge(WINDOW + 1);
    expect(older.wall.state).toBe("wall_DOWN");
    expect(older.wall.reasons).toContain("canary_failed");
  });

  it("keeps the wall OK at every reader second of a schedule firing every CANARY_PERIOD up to the leeway late, which a 60-second window would fail", () => {
    // Worst spacing: one drop on time, the next a full leeway late.
    const gap = CANARY_PERIOD + LEEWAY_MS;
    let shortWindowWouldFail = false;
    for (let age = 0; age <= gap; age += SECOND) {
      const envelope = withCanaryAge(age);
      expect(envelope.wall.state.startsWith("wall_OK_"), `age ${age}: ${envelope.wall.reasons.join(",")}`).toBe(true);
      if (age > SHORT_RECORDING_WINDOW) shortWindowWouldFail = true;
    }
    expect(shortWindowWouldFail).toBe(true);
    expect(WINDOW).toBeGreaterThan(gap);
    expect(SHORT_RECORDING_WINDOW).toBeLessThan(CANARY_PERIOD);
  });
});
