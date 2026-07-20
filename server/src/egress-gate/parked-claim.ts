/**
 * THE PARKED-CLAIM CHOKEPOINT (fix-round 4, 2026-07-19).
 *
 * WHY THIS MODULE EXISTS. Across four adversarial gate rounds this subsystem
 * produced the SAME defect SIX times: it told a caller (or the operator) that
 * the agent was PARKED / stopped / not running on the strength of CONTROL FLOW
 * -- a bootout resolved, a start threw, a catch branch was reached -- rather
 * than on the strength of an OBSERVATION. Round 3 fixed the pattern at one
 * site (the initial reassert) and BOTH remaining sites of the identical shape
 * survived into round 4:
 *
 *   - the release sequence's bootstrap / verify-running ABORT cleanups
 *     returned a clean `kind: "parked"` after `bootoutJob` resolved, with no
 *     settled `harnessStatus` read-back (Codex HIGH-1, reproduced host-free
 *     with the modelled harness at `running: true, pid: 4242`);
 *   - `degradeLoud`'s `harnessStartedCoarse: false` -- which means "we did not
 *     start it" -- was RENDERED at four altitudes, ending at the operator CLI,
 *     as "The agent is PARKED (not running)", over the very process the new
 *     reassert gate had just refused to proceed past BECAUSE it was running
 *     (Claude HIGH-1, pid 9001 alive throughout the captured output).
 *
 * Six instances of one pattern is not a run of bad luck and it is not a set of
 * six bugs. It is a missing chokepoint. So:
 *
 * THE RULE THIS MODULE ENFORCES STRUCTURALLY. A parked claim -- in a returned
 * outcome, in a flag, or in printed prose -- may exist ONLY as a
 * {@link ParkedClaim}, and {@link assessHarnessParked} is the ONLY function
 * that can construct one. The type carries a module-private brand, so a
 * hand-rolled object literal of the same shape is a COMPILE ERROR in every
 * other module. There is no "add a second probe next to the third site"
 * available: to say anything about the agent's run state you must come
 * through here, and coming through here means a settled observation happened
 * or the claim is explicitly weakened.
 *
 * THREE STATES, NOT A BOOLEAN. The other half of the round-4 diagnosis is that
 * a boolean carries TWO claims and reviewers (and the claim register) audit
 * only the `true` one. `harnessStartedCoarse` was correctly `observed` for its
 * true branch; nothing described what `false` was rendered to mean, and the
 * false branch is where the falsehood lived. So this module has no boolean:
 *
 *   - `parked`  -- a settled launchd read reported a trustworthy state with NO
 *                  pid. The only state that may be called parked.
 *   - `alive`   -- a pid was observed. Fails closed AWAY from parked.
 *   - `unknown` -- launchd could not be read, the probe threw, or the caller
 *                  could not probe at all. "I could not tell" is not a park.
 *
 * Each state carries its OWN operator sentence, so no caller is left composing
 * prose from a flag. Rendering surfaces print {@link ParkedClaim.sentence};
 * they never branch on run state themselves. `claim-basis-structural.test.ts`
 * enforces that with a PARSER-based scan of every string and template literal
 * in the subsystem plus `wrap/cli.ts`: parked-assertion prose outside this
 * file fails the build.
 *
 * WHY `pid` IS CHECKED SEPARATELY FROM `running` (load-bearing, keep it).
 * Production wires `harnessStatus` to downgrade `running` to false when the
 * pid is not STABLE across samples. That is the right bar for "did it come
 * up?" and exactly the wrong bar for "is it gone?": a crash-looping pre-G5
 * harness is a LIVE process that reads as not-running. For the stopped
 * direction any pid at all is disqualifying.
 *
 * WHAT THIS MODULE DOES NOT CLAIM. `parked` here is "the harness process is
 * not running", NOT the FULL PERSISTENT parked posture (not running + job
 * disabled in launchd's override database + hold file absent + parked plist on
 * disk). That stronger property is `verifyParkedPersistent` on the repair
 * path; a `parked` claim from here says nothing about whether the agent can
 * return at the next boot, and its sentence is worded to not imply otherwise.
 */

import {
  awaitHarnessStoppedVia,
  type HarnessDaemonStatus,
} from "./harness-daemon.js";

/**
 * Module-private brand. Not exported, so no other module can produce a value
 * assignable to {@link ParkedClaim}: an object literal with the same visible
 * fields fails to typecheck outside this file. This is what makes
 * {@link assessHarnessParked} the SOLE constructor structurally rather than by
 * convention -- a compile error, not a review miss.
 */
declare const PARKED_CLAIM_BRAND: unique symbol;

interface ParkedClaimBase {
  readonly [PARKED_CLAIM_BRAND]: true;
  /**
   * The single sentence a rendering surface may print about the agent's run
   * state. Callers print this; they never compose their own.
   */
  readonly sentence: string;
}

/**
 * What is known about the agent harness's run state, and on what basis.
 *
 * Deliberately three named states rather than a boolean: a boolean would put
 * "observed stopped", "observed running" and "could not tell" on the same
 * false/true axis, which is the exact shape that let the round-4 defect render
 * "we did not start it" as "it is not running".
 */
export type ParkedClaim =
  | (ParkedClaimBase & {
      readonly state: "parked";
      /** What was actually read back. Never empty. */
      readonly observed: string;
    })
  | (ParkedClaimBase & {
      readonly state: "alive";
      /** What was actually read back (the pid that disqualifies the park). */
      readonly observed: string;
      /** The observed pid, when launchd reported one. */
      readonly pid?: number;
    })
  | (ParkedClaimBase & {
      readonly state: "unknown";
      /** Precisely what could NOT be read back. Never empty. */
      readonly unobserved: string;
    });

/**
 * The settled-status probe {@link assessHarnessParked} needs. Structurally
 * satisfied by `ReleaseBarrierOps` (which already exposes exactly these two),
 * so the release sequence passes its own ops straight through.
 */
export interface ParkedClaimProbeOps {
  /**
   * The harness job's launchd status. MUST carry `pid` through even when it
   * downgrades `running` to false -- see the module header.
   */
  harnessStatus(): Promise<HarnessDaemonStatus>;
  /** Sleep between settle samples. Tests inject a no-op for an instant loop. */
  sleepMs?(ms: number): Promise<void>;
}

/**
 * Why a caller could not probe at all. Forces the caller to say what it did
 * and did not observe rather than fall back to an unqualified parked sentence.
 */
export interface ParkedClaimUnprobed {
  /** Plain-words reason no observation exists (goes into `unobserved`). */
  readonly cannotProbe: string;
}

/**
 * THE SOLE CONSTRUCTOR of a parked claim.
 *
 * With `{ probe }`: settles through the SHARED
 * `awaitHarnessStoppedVia` loop (20 x 250ms; the same loop the daemon's stop
 * assertions use, so the three sites cannot drift), then classifies. A
 * trustworthy launchd state with NO pid is `parked`; any pid is `alive`; an
 * untrustworthy state or a throwing probe is `unknown`.
 *
 * With `{ cannotProbe }`: returns `unknown` carrying the caller's reason. This
 * is the WEAKENED form the brief requires of a caller that genuinely cannot
 * observe -- it names what it did not see and never yields the parked
 * sentence.
 *
 * NEVER THROWS. A probe that throws becomes `unknown`, because a thrown probe
 * is exactly the case where a caller would otherwise be tempted to fall back
 * to control flow.
 */
export async function assessHarnessParked(
  source: { readonly probe: ParkedClaimProbeOps } | ParkedClaimUnprobed,
): Promise<ParkedClaim> {
  if ("cannotProbe" in source) {
    return unknownClaim(source.cannotProbe);
  }

  let status: HarnessDaemonStatus;
  try {
    status = await awaitHarnessStoppedVia(
      () => source.probe.harnessStatus(),
      source.probe.sleepMs,
    );
  } catch (err) {
    return unknownClaim(
      `the launchd status probe errored (${err instanceof Error ? err.message : String(err)})`,
    );
  }

  if (!status.known) {
    return unknownClaim("launchctl did not return a trustworthy harness status");
  }
  if (status.running || status.pid !== undefined) {
    const pidText = status.pid !== undefined ? String(status.pid) : "unknown";
    return brand({
      state: "alive",
      observed: `a settled launchd read still reports a pid (${pidText}) for the harness job`,
      ...(status.pid !== undefined ? { pid: status.pid } : {}),
      sentence:
        `The agent is RUNNING (pid ${pidText}): a settled launchd read still reports a live process ` +
        "for the harness job, so this run did NOT park it. Treat the agent as up.",
    });
  }
  return brand({
    state: "parked",
    observed: "a settled launchd read reports a trustworthy harness status with no pid",
    sentence:
      "The agent is PARKED (not running): a settled launchd read reports no process for the harness job. " +
      "(Run state only -- this does not assert the persistent boot state was re-parked.)",
  });
}

function unknownClaim(unobserved: string): ParkedClaim {
  return brand({
    state: "unknown",
    unobserved,
    sentence:
      `The agent's run state could NOT be established (${unobserved}); this run did not observe it stop. ` +
      "Treat the agent as POSSIBLY RUNNING.",
  });
}

/**
 * The single branding point. Private: everything above funnels through
 * {@link assessHarnessParked}, so this is never a back door.
 */
function brand<T extends Omit<ParkedClaim, typeof PARKED_CLAIM_BRAND>>(claim: T): ParkedClaim {
  return claim as unknown as ParkedClaim;
}

/**
 * What the degrade path did with the harness. The `started-coarse` branch is
 * an OBSERVATION (production's `startHarnessCoarse` completes through
 * `installAgentHarnessDaemon`, which requires a stable running pid); the
 * `not-started` branch carries a {@link ParkedClaim} rather than a boolean,
 * so "we did not start it" can never again be rendered as "it is not running".
 */
export type HarnessDisposition =
  | {
      /**
       * BRANDED (fix-round 5). The round-5 gate's LOW-4: `ParkedClaim` was
       * unforgeable while the POSITIVE assertion that reaches the operator --
       * "The agent is RUNNING in coarse-only mode" -- was free-form prose any
       * module could construct. "Unforgeable" is this round's central claim,
       * so it now holds on both arms: {@link startedCoarseDisposition} is the
       * sole constructor, structurally, and the sentence is not a parameter.
       */
      readonly [PARKED_CLAIM_BRAND]: true;
      readonly disposition: "started-coarse";
      readonly observed: string;
      readonly sentence: string;
    }
  | {
      readonly disposition: "not-started";
      readonly claim: ParkedClaim;
    };

/**
 * The ONLY constructor of the observed `started-coarse` disposition. Callers
 * may build the `not-started` branch directly because its whole content is a
 * {@link ParkedClaim}, which they cannot forge.
 */
export function startedCoarseDisposition(): HarnessDisposition {
  return {
    disposition: "started-coarse",
    observed: "the coarse harness install completed, which requires a stable running pid",
    sentence:
      "The agent is RUNNING in coarse-only mode (network-destination wall, no fine-grained gate).",
  } as unknown as HarnessDisposition;
}

/**
 * The MACHINE-READABLE form of a claim, for audit records (fix-round 5).
 *
 * Round 4's diagnosis had two halves: the operator prose was false, AND a
 * downstream consumer reading the record saw a bare token with no run-state
 * field at all, which made the falsehood silent rather than merely
 * self-contradictory. `degradeLoud` was fixed to emit these two fields; the
 * boot-release audit was not, and the round-5 gate found the asymmetry. One
 * exported shape so the two records cannot drift into disagreeing about what
 * they are called or what the basis is.
 */
export function parkedClaimAuditFields(claim: ParkedClaim): {
  harness_run_state: string;
  harness_run_state_basis: string;
} {
  return { harness_run_state: claim.state, harness_run_state_basis: claim.sentence };
}

/** The operator sentence for a disposition, from whichever branch it is. */
export function harnessDispositionSentence(disposition: HarnessDisposition): string {
  return disposition.disposition === "started-coarse"
    ? disposition.sentence
    : disposition.claim.sentence;
}

// ---------------------------------------------------------------------------
// THE RECOVERY IMPERATIVE (fix-round 6, 2026-07-19)
// ---------------------------------------------------------------------------

/**
 * Where the operator can look, for a recovery instruction that names a place.
 * Structurally satisfied by `HarnessStandDownSnapshot`, so the revert paths
 * pass their own snapshot straight through.
 */
export interface HarnessRecoveryLocator {
  readonly plistPath: string;
  readonly harnessLabel: string;
}

/**
 * A run-state SENTENCE plus the recovery INSTRUCTION that follows from it.
 *
 * WHY THIS TYPE EXISTS (the round-6 diagnosis, worth stating in full because
 * five rounds of fixes missed it). Round 4 built the `ParkedClaim` chokepoint
 * so that a DESCRIPTION of the agent's run state could only come from an
 * observation. Round 5 threaded a claim into the parked install's own undo.
 * Round 6's gate then found the eleventh instance of the same defect one hop
 * away, in a sentence no part of that machinery governed:
 *
 *     "This run did NOT bring it back up, and did not verify its run state.
 *      Re-run 'sudo sanctuary protect --hermes' to bring it back up under the
 *      previous (coarse) posture."
 *
 * ...printed over a harness the run had probed twenty times and observed ALIVE
 * at pid 9001. The claim was obtained three frames down and DISCARDED at an op
 * boundary whose result type had no run-state field.
 *
 * Two things had gone unnoticed, and this type closes both:
 *
 *   1. **An instruction premised on a state is a claim about that state.**
 *      "Re-run to bring it back up" asserts that there is something down to
 *      bring up. The run-state prose guard governed only DESCRIPTIONS, so the
 *      imperative matched no pattern and the build stayed green. The
 *      imperative now lives HERE, in the sole-owner file, and
 *      {@link RUN_STATE_PROSE_PATTERNS} covers its phrasings -- so composing
 *      one anywhere else fails the build.
 *
 *   2. **Routing the DECISION is not routing the CLAIM.** The orchestrator's
 *      outcome chokepoint decided, in one place, whether to restore. What got
 *      PRINTED about that restore was rebuilt at each consumer. So the advice
 *      is now a branded value: a consumer receives it or renders nothing, and
 *      cannot compose a second copy that drifts.
 *
 * Consumers print {@link RunStateAdvice.text}. They never branch on
 * {@link RunStateAdvice.claim} to choose words -- it is exposed so a caller
 * that needs the STATE (an audit field, a test) has it without re-deriving.
 */
export interface RunStateAdvice {
  readonly [PARKED_CLAIM_BRAND]: true;
  /** The full operator-facing text: the run-state sentence plus the recovery step. */
  readonly text: string;
  /** The observation the text was derived from. */
  readonly claim: ParkedClaim;
}

/**
 * THE SOLE CONSTRUCTOR of run-state advice.
 *
 * Takes a {@link ParkedClaim} by value rather than a probe, because the honest
 * moment to read the harness is after the last restore attempt, which only the
 * caller knows. It cannot be called without one, which is the point.
 *
 * `priorPlistRestored: false` suppresses the "under the previous (coarse)
 * posture" promise on the parked branch (round-6 gate, Finding 4): a re-run
 * renders a FRESH coarse plist, and when this run could not put the operator's
 * prior bytes back, those bytes are gone. Omit it when the caller genuinely
 * does not know; the neutral wording is used and nothing is promised.
 */
export function runStateAdvice(
  claim: ParkedClaim,
  context?: {
    readonly locator?: HarnessRecoveryLocator;
    readonly priorPlistRestored?: boolean;
  },
): RunStateAdvice {
  const locator = context?.locator;
  const where =
    locator !== undefined
      ? `${locator.plistPath} and 'sudo launchctl print system/${locator.harnessLabel}'`
      : "the harness plist and its launchd job";
  let recovery: string;
  if (claim.state === "parked") {
    recovery =
      context?.priorPlistRestored === false
        ? "Re-run 'sudo sanctuary protect --hermes' to bring it back up -- but NOT under your previous " +
          "configuration: this run could not put the previous harness plist back, so the re-run renders a " +
          "fresh coarse plist rather than your prior bytes."
        : "Re-run 'sudo sanctuary protect --hermes' to bring it back up under the previous (coarse) posture.";
  } else if (claim.state === "alive") {
    recovery =
      `Do NOT re-run 'sudo sanctuary protect --hermes' expecting it to restart the agent: a live process ` +
      `is there. Inspect ${where} first -- re-running would stand that process down again and hit the same ` +
      "failure.";
  } else {
    recovery =
      `Establish the harness's state before re-running (${where}): 'sudo sanctuary protect --hermes' ` +
      "assumes it has to bring the agent up.";
  }
  return { text: `${claim.sentence} ${recovery}`, claim } as unknown as RunStateAdvice;
}
