/**
 * Slice M emission-liveness watchdog tests.
 *
 * The watchdog is the decided-vs-emitted DIVERGENCE detector (the honest #946
 * follow-up): it must fail LOUD when enforcement decisions keep arriving but
 * audit emission has stopped, stay QUIET on a healthy interleaved stream,
 * NEVER fire at zero traffic, and CLEAR the finding on recovery.
 *
 * Each assertion below fails against pre-change code because the module did
 * not exist before this branch (the import would not resolve). The behavioral
 * cases pin the exact divergence semantics.
 */

import { describe, it, expect } from "vitest";

import {
  DEFAULT_EMISSION_STALL_GRACE_MS,
  DEFAULT_EMISSION_STALL_MIN_DECISIONS,
  EmissionLivenessWatchdog,
  type EmissionRecoveryFinding,
  type EmissionStallFinding,
} from "../../../src/castle-wall/audit/emission-liveness.js";

/** A controllable clock: `advance(ms)` moves it forward. */
function makeClock(startMs = 1_000_000): { now: () => number; advance: (ms: number) => void } {
  let t = startMs;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

interface Captured {
  stalls: EmissionStallFinding[];
  recoveries: EmissionRecoveryFinding[];
}

function makeWatchdog(
  overrides: { graceMs?: number; minDecisions?: number; now?: () => number } = {}
): { wd: EmissionLivenessWatchdog; captured: Captured } {
  const captured: Captured = { stalls: [], recoveries: [] };
  const wd = new EmissionLivenessWatchdog({
    ...(overrides.now ? { now: overrides.now } : {}),
    ...(overrides.graceMs !== undefined ? { graceMs: overrides.graceMs } : {}),
    ...(overrides.minDecisions !== undefined ? { minDecisions: overrides.minDecisions } : {}),
    onStall: (f) => captured.stalls.push(f),
    onRecovery: (f) => captured.recoveries.push(f),
  });
  return { wd, captured };
}

describe("EmissionLivenessWatchdog", () => {
  it("fires a stall exactly once when decisions continue but emission stops", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ graceMs: 60_000, minDecisions: 2, now: clock.now });

    // Two decisions arrive, no emission.
    wd.noteDecision("flow_decision_recorded");
    clock.advance(1_000);
    wd.noteDecision("flow_decision_recorded");

    // Before the grace window elapses: no stall.
    clock.advance(30_000);
    expect(wd.evaluate()).toBeNull();
    expect(captured.stalls).toHaveLength(0);

    // Grace window elapses (anchor was the FIRST decision): stall fires.
    clock.advance(31_000); // total 61s since the first decision
    const finding = wd.evaluate();
    expect(finding).not.toBeNull();
    expect(finding?.kind).toBe("emission_stall");
    expect(finding?.decidedSinceLastEmission).toBe(2);
    expect(finding?.emittedTotal).toBe(0);
    expect(finding?.msSinceLastEmissionMs).toBeNull(); // never emitted
    expect(captured.stalls).toHaveLength(1);

    // Idempotent: a second evaluate during the same episode does not re-fire.
    clock.advance(60_000);
    wd.noteDecision("flow_decision_recorded");
    clock.advance(60_000);
    expect(wd.evaluate()).toBeNull();
    expect(captured.stalls).toHaveLength(1);
  });

  it("stays quiet on a healthy interleaved decided/emitted stream", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ graceMs: 60_000, minDecisions: 2, now: clock.now });

    for (let i = 0; i < 50; i += 1) {
      wd.noteDecision("flow_decision_recorded");
      clock.advance(500);
      wd.noteEmission();
      clock.advance(500);
      expect(wd.evaluate()).toBeNull();
    }
    expect(captured.stalls).toHaveLength(0);
    expect(captured.recoveries).toHaveLength(0);
    const snap = wd.snapshot();
    expect(snap.decidedTotal).toBe(50);
    expect(snap.emittedTotal).toBe(50);
    expect(snap.decidedSinceLastEmission).toBe(0);
    expect(snap.stalled).toBe(false);
  });

  it("NEVER fires at zero traffic (idle wall is healthy, not stalled)", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ graceMs: 1_000, minDecisions: 2, now: clock.now });

    // Advance far past any grace window with no decisions at all.
    for (let i = 0; i < 100; i += 1) {
      clock.advance(10_000);
      expect(wd.evaluate()).toBeNull();
    }
    expect(captured.stalls).toHaveLength(0);
    expect(wd.snapshot().decidedTotal).toBe(0);
  });

  it("does NOT fire when decisions stay below the minimum, even past the grace window", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ graceMs: 10_000, minDecisions: 2, now: clock.now });

    // Exactly one decision, no emission, long wait.
    wd.noteDecision("flow_decision_recorded");
    clock.advance(1_000_000);
    expect(wd.evaluate()).toBeNull();
    expect(captured.stalls).toHaveLength(0);

    // The second decision plus grace crosses the threshold.
    wd.noteDecision("flow_decision_recorded");
    clock.advance(10_001);
    expect(wd.evaluate()).not.toBeNull();
    expect(captured.stalls).toHaveLength(1);
  });

  it("clears the finding and reports recovery when emission resumes during a stall", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ graceMs: 10_000, minDecisions: 2, now: clock.now });

    wd.noteDecision("flow_decision_recorded");
    wd.noteDecision("flow_decision_recorded");
    clock.advance(10_001);
    expect(wd.evaluate()).not.toBeNull();
    expect(wd.snapshot().stalled).toBe(true);

    // More decisions arrive during the stall.
    wd.noteDecision("flow_decision_recorded");
    clock.advance(5_000);

    // Emission resumes -> recovery fires, stall clears.
    wd.noteEmission();
    expect(captured.recoveries).toHaveLength(1);
    expect(captured.recoveries[0]?.kind).toBe("emission_recovered");
    expect(captured.recoveries[0]?.decidedDuringStall).toBe(1);
    expect(captured.recoveries[0]?.stallDurationMs).toBe(5_000);
    expect(wd.snapshot().stalled).toBe(false);
    expect(wd.snapshot().decidedSinceLastEmission).toBe(0);

    // A fresh stall episode can fire again after recovery.
    wd.noteDecision("flow_decision_recorded");
    wd.noteDecision("flow_decision_recorded");
    clock.advance(10_001);
    expect(wd.evaluate()).not.toBeNull();
    expect(captured.stalls).toHaveLength(2);
  });

  it("resets the grace anchor on every emission so a slow-but-live stream never fires", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ graceMs: 10_000, minDecisions: 2, now: clock.now });

    // Decisions and emissions each 9s apart: decidedSinceLastEmission never
    // exceeds 1 at evaluate time, and the anchor resets each emission.
    for (let i = 0; i < 20; i += 1) {
      wd.noteDecision("flow_decision_recorded");
      clock.advance(9_000);
      expect(wd.evaluate()).toBeNull();
      wd.noteEmission();
      clock.advance(1_000);
    }
    expect(captured.stalls).toHaveLength(0);
  });

  it("counts rejections without treating them as emissions (chain-reject burst still diverges)", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ graceMs: 10_000, minDecisions: 2, now: clock.now });

    // Decisions arrive and are all REJECTED (audit chain gate), never emitted.
    wd.noteDecision("flow_decision_recorded");
    wd.noteRejection("audit_chain:bad");
    clock.advance(1_000);
    wd.noteDecision("flow_decision_recorded");
    wd.noteRejection("audit_chain:bad");
    clock.advance(10_001);

    const finding = wd.evaluate();
    expect(finding).not.toBeNull();
    expect(finding?.rejectedTotal).toBe(2);
    expect(finding?.emittedTotal).toBe(0);
    expect(captured.stalls).toHaveLength(1);
  });

  it("attributes decisions by source in the finding", () => {
    const clock = makeClock();
    const { wd } = makeWatchdog({ graceMs: 10_000, minDecisions: 2, now: clock.now });

    wd.noteDecision("flow_decision_recorded");
    wd.noteDecision("agent_egress_probe");
    clock.advance(10_001);
    const finding = wd.evaluate();
    expect(finding?.decidedBySource).toEqual({
      flow_decision_recorded: 1,
      agent_egress_probe: 1,
    });
  });

  it("uses documented defaults when grace / minDecisions are omitted", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ now: clock.now });

    for (let i = 0; i < DEFAULT_EMISSION_STALL_MIN_DECISIONS; i += 1) {
      wd.noteDecision("flow_decision_recorded");
    }
    clock.advance(DEFAULT_EMISSION_STALL_GRACE_MS - 1);
    expect(wd.evaluate()).toBeNull();
    clock.advance(2);
    expect(wd.evaluate()).not.toBeNull();
    expect(captured.stalls).toHaveLength(1);
  });

  it("rejects an invalid grace window at construction (fail-closed config)", () => {
    expect(
      () =>
        new EmissionLivenessWatchdog({
          graceMs: 0,
          onStall: () => {},
          onRecovery: () => {},
        })
    ).toThrow(/graceMs/);
    expect(
      () =>
        new EmissionLivenessWatchdog({
          graceMs: Number.NaN,
          onStall: () => {},
          onRecovery: () => {},
        })
    ).toThrow(/graceMs/);
  });

  it("rejects an invalid minDecisions at construction (fail-closed config)", () => {
    expect(
      () =>
        new EmissionLivenessWatchdog({
          minDecisions: 0,
          onStall: () => {},
          onRecovery: () => {},
        })
    ).toThrow(/minDecisions/);
    expect(
      () =>
        new EmissionLivenessWatchdog({
          minDecisions: 1.5,
          onStall: () => {},
          onRecovery: () => {},
        })
    ).toThrow(/minDecisions/);
  });

  it("commits the stall transition BEFORE the callback so a throwing callback cannot re-fire", () => {
    const clock = makeClock();
    let calls = 0;
    const wd = new EmissionLivenessWatchdog({
      now: clock.now,
      graceMs: 10_000,
      minDecisions: 2,
      onStall: () => {
        calls += 1;
        throw new Error("callback boom");
      },
      onRecovery: () => {},
    });

    wd.noteDecision("flow_decision_recorded");
    wd.noteDecision("flow_decision_recorded");
    clock.advance(10_001);
    expect(() => wd.evaluate()).toThrow(/boom/);
    // State was committed before the throw: stalled, and a re-evaluate no-ops.
    expect(wd.snapshot().stalled).toBe(true);
    clock.advance(10_000);
    wd.noteDecision("flow_decision_recorded");
    clock.advance(10_000);
    expect(wd.evaluate()).toBeNull();
    expect(calls).toBe(1);
  });

  it("stamps lastEvaluateAtMs on EVERY evaluate call, including early returns (watchdog self-liveness signal)", () => {
    const clock = makeClock(2_000_000);
    const { wd } = makeWatchdog({ graceMs: 60_000, minDecisions: 2, now: clock.now });

    // Never evaluated: the pulse is null (a never-started tick is visible).
    expect(wd.snapshot().lastEvaluateAtMs).toBeNull();

    // An early-return evaluate (zero decisions) still stamps the pulse: the
    // signal tracks the TICK TIMER's liveness, not stall proximity.
    expect(wd.evaluate()).toBeNull();
    expect(wd.snapshot().lastEvaluateAtMs).toBe(2_000_000);

    // Ticks stopped (no further evaluate calls): the pulse goes stale while
    // the clock advances, which is exactly what a heartbeat reader compares
    // against to detect a cleared tick timer.
    clock.advance(300_000);
    expect(wd.snapshot().lastEvaluateAtMs).toBe(2_000_000);

    // A later tick advances it again.
    expect(wd.evaluate()).toBeNull();
    expect(wd.snapshot().lastEvaluateAtMs).toBe(2_300_000);
  });

  it("standDown clears the unemitted run and an active stall episode WITHOUT invoking the recovery callback", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ graceMs: 10_000, minDecisions: 2, now: clock.now });

    // Mature a real stall episode.
    wd.noteDecision("flow_decision_recorded");
    wd.noteDecision("flow_decision_recorded");
    clock.advance(10_001);
    expect(wd.evaluate()).not.toBeNull();
    expect(captured.stalls).toHaveLength(1);
    expect(wd.snapshot().stalled).toBe(true);

    // Deliberate stand-down: the episode ends unresolved. NOT a recovery
    // (nothing recovered), so the recovery callback must not fire.
    wd.standDown();
    const snap = wd.snapshot();
    expect(snap.stalled).toBe(false);
    expect(snap.stallStartedAtMs).toBeNull();
    expect(snap.decidedSinceLastEmission).toBe(0);
    expect(snap.firstUnemittedDecisionAtMs).toBeNull();
    expect(captured.recoveries).toHaveLength(0);
    // Monotonic totals survive for diagnostics.
    expect(snap.decidedTotal).toBe(2);

    // Post-stand-down, no residue can mature into a stall.
    clock.advance(60_000);
    expect(wd.evaluate()).toBeNull();
    expect(captured.stalls).toHaveLength(1);

    // The detector is NOT weakened: fresh divergence after a stand-down
    // (e.g. a re-armed wall) fires normally.
    wd.noteDecision("flow_decision_recorded");
    wd.noteDecision("flow_decision_recorded");
    clock.advance(10_001);
    expect(wd.evaluate()).not.toBeNull();
    expect(captured.stalls).toHaveLength(2);
  });

  it("standDown on a pre-stall run prevents that run from ever firing", () => {
    const clock = makeClock();
    const { wd, captured } = makeWatchdog({ graceMs: 10_000, minDecisions: 2, now: clock.now });

    wd.noteDecision("flow_decision_recorded");
    wd.noteDecision("flow_decision_recorded");
    // Stand down BEFORE the grace window matures.
    clock.advance(5_000);
    wd.standDown();
    clock.advance(60_000);
    expect(wd.evaluate()).toBeNull();
    expect(captured.stalls).toHaveLength(0);
  });
});
