/**
 * Unified Protect Slice 5 S5-6: the exclusive-egress ARMING stage, the
 * `--repair-egress-gate` repair sequence, and the boot release sequence --
 * the PURE drivers `runProvisionFlow`, the repair verb, and the Castle Wall
 * boot daemon route through (design rev3
 * `Unified_Protect_Slice5_InstallFusion_Design_2026-07-14.md`, S5-6 row:
 * orchestrate wiring + repair verb + drift guard MED-7).
 *
 * WHAT THIS RETIRES: the S5-1..S5-5 egress-gate cluster shipped as libraries
 * with "no production caller" honesty disclosures. This module is that
 * caller's sequencing layer: the install flow (orchestrate.ts) and the boot
 * daemon now route through {@link runExclusiveEgressArming} /
 * {@link runBootExclusiveEgressRelease}, and the repair verb through
 * {@link runEgressGateRepair}. The Erik-present S5-DRILL is still owed; no
 * capability claim advances here.
 *
 * FAIL-CLOSED DIRECTION (spawn contract, design BLOCKER-2): every failure
 * path lands in exactly one of two honest states -- (a) the agent is NOT
 * RUNNING (parked: hold file removed, job disabled), or (b) DEGRADE-LOUD:
 * the proven coarse wall stays armed, the manifest is explicitly recomposed
 * back to coarse scope through the S5-4 coarse-only composition (audited,
 * residue-checked), and the outcome is the DISTINCT non-green
 * `exclusive-egress-unarmed-coarse-active` state that S5-P renders amber on
 * every surface. No path leaves the agent released with the gate unverified,
 * and no path reports green without positive evidence.
 *
 * All side effects are injected ops so every branch is unit-testable
 * host-free; the production wiring lives in `egress-gate/arming-wiring.ts`
 * (install/repair) and the boot daemon.
 */

import type {
  ReleaseBarrierOutcome,
} from "../../egress-gate/release-barrier.js";
import type { PfAnchorQuarantineRepairResult } from "../../egress-gate/anchor-registry.js";
import {
  harnessDispositionSentence,
  startedCoarseDisposition,
  type HarnessDisposition,
  type ParkedClaim,
} from "../../egress-gate/parked-claim.js";

/** Distinct local audit operation strings (never a widened shared enum). */
export const EXCLUSIVE_EGRESS_ARMED_AUDIT_OP = "exclusive_egress_armed";
export const EXCLUSIVE_EGRESS_DEGRADED_AUDIT_OP = "exclusive_egress_degraded_coarse_active";
export const EGRESS_GATE_REPAIR_AUDIT_OP = "egress_gate_repair";
export const EGRESS_GATE_REPAIR_REFUSED_AUDIT_OP = "egress_gate_repair_refused";
export const EGRESS_GATE_REPAIR_OVERRIDE_AUDIT_OP = "egress_gate_repair_override";
export const EGRESS_GATE_REPAIR_QUARANTINE_AUDIT_OP = "egress_gate_repair_quarantine";

/** The committed identity the stage keys the release on (S5-2 G5 output). */
export interface ExclusiveGenerationIdentity {
  generation_id: number;
  agent_uid: number;
  gate_port: number;
}

/**
 * Injected side effects for the exclusive-egress arming stage. Production
 * (`egress-gate/arming-wiring.ts`) maps these onto the REAL primitives:
 * gate-account provisioning, the S5-2 `GenerationCoordinator` (G1-G5: bind ->
 * owner-check -> S5-1 registry pf arm -> gate policy + exclusive-marker
 * publish -> commit), the gate LaunchDaemon install, the S5-3 oracle, and the
 * S5-5 `runReleaseBarrierSequence`.
 */
export interface ExclusiveEgressArmOps {
  /**
   * Bring up a committed exclusive-egress generation for the agent: the S5-2
   * G1-G5 sequence, which (production) writes the gate policy file, arms the
   * pf anchor through the S5-1 locked registry, re-scopes the provisioned
   * manifest rules to the gate principal + publishes the exclusive routing
   * marker (the S5-4 composition path), installs + bootstraps the gate
   * daemon, and commits. Throws on any failure (the generation machine's own
   * recovery has already tombstoned fail-closed by the time the throw
   * surfaces).
   */
  bringUpGeneration(): Promise<ExclusiveGenerationIdentity>;
  /**
   * The S5-5 release barrier (production: `runReleaseBarrierSequence` with
   * root launchctl/hold-file/oracle-verify ops). The ONLY path that may start
   * the parked harness; "released" requires the committed generation
   * re-verified live strictly before enable+bootstrap.
   */
  runReleaseSequence(committed: ExclusiveGenerationIdentity): Promise<ReleaseBarrierOutcome>;
  /**
   * DEGRADE-LOUD manifest restore: explicitly recompose the manifest back to
   * COARSE scope through the S5-4 coarse-only composition -- republish the
   * provisioned rules agent-scoped, run the residue check, emit the REQUIRED
   * `exclusive_routing_coarse_fallback` audit record, remove the exclusive
   * routing marker + gate policy file, and reload the signing daemon. Throws
   * on failure (the caller then reports the agent parked + non-functional
   * LOUDLY rather than starting it over an exclusive-scoped manifest).
   */
  restoreCoarseComposition(reason: string): Promise<void>;
  /**
   * Start the harness in COARSE mode after a successful coarse restore (the
   * degrade-loud path's "the coarse wall is proven protection" semantics):
   * production re-renders the PLAIN (non-barrier) harness plist and
   * enables+bootstraps it. Throws on failure; the outcome then reports the
   * agent NOT running (fail-closed toward agent-down, never unconfined).
   */
  startHarnessCoarse(): Promise<void>;
  /**
   * THE parked-claim probe (fix-round 4). Production wires this to
   * `assessHarnessParked({ probe: { harnessStatus, sleepMs } })`. The degrade
   * path calls it whenever it did NOT start the agent, because "we did not
   * start it" is a fact about this run and says nothing about whether a
   * process is alive -- which is exactly what the round-4 HIGH found being
   * rendered to the operator as "The agent is PARKED (not running)" over a
   * live pid 9001. MUST NOT throw (`assessHarnessParked` never does).
   */
  assessHarnessParked(): Promise<ParkedClaim>;
  /**
   * Best-effort audit through the existing castle-wall CLI audit path with a
   * DISTINCT operation string. MUST never throw.
   */
  audit(operation: string, details: Record<string, unknown>): Promise<void>;
  /** Operator-facing progress line. */
  print(line: string): void;
}

/** Terminal outcome of the exclusive-egress arming stage. */
export type ExclusiveEgressArmOutcome =
  /** Fully live: generation committed, barrier released the harness. */
  | { kind: "exclusive-armed"; generationId: number }
  /**
   * Live but AMBER: the harness is running confined, but the persistent boot
   * state could not be re-parked (next boot could auto-start pre-G5). Never
   * rendered green; the repair verb re-runs the re-park.
   */
  | { kind: "exclusive-armed-repark-failed"; generationId: number; reparkError: string }
  /**
   * DEGRADE-LOUD (design answer 2 choice (b)): the exclusive stack could not
   * come live; the coarse wall stays armed. Always a DISTINCT non-green
   * posture (S5-P renders it amber everywhere).
   *
   * `coarseCompositionRestored` reports whether the manifest is back in coarse
   * (agent-functional) scope. Its TRUE branch is observed (the S5-4 compose
   * ran its residue check and emitted the required audit); its FALSE branch
   * asserts only that OUR restore failed -- it makes no claim about the
   * agent's run state, which is `harness` and nothing else.
   *
   * `harness` replaced the former `harnessStartedCoarse: boolean` in fix-round
   * 4. That boolean was correctly `observed` for its true branch, and its
   * FALSE branch -- which means "this run did not start it" -- was rendered at
   * four altitudes, ending at the operator CLI, as "The agent is PARKED (not
   * running)", over a process the release barrier had just refused to proceed
   * past BECAUSE it was running. A boolean carries two claims and only one of
   * them was ever audited, so the field is now a named-branch union whose
   * not-started arm carries an unforgeable {@link ParkedClaim}.
   */
  | {
      kind: "degraded-coarse-active";
      stage: "bring-up" | "release";
      reason: string;
      coarseCompositionRestored: boolean;
      /** What happened to the agent process, per branch. Never a boolean. */
      harness: HarnessDisposition;
      /** Cleanup problems that must stay loud (parked-state assertions etc). */
      cleanupErrors: string[];
    };

/**
 * Run the exclusive-egress arming stage: bring-up -> release barrier ->
 * outcome mapping, with the degrade-loud coarse fallback on every failure.
 * The caller (orchestrate.ts) runs this ONLY after the coarse stages proved
 * live (wall armed + as-uid egress verified) and ONLY when the harness was
 * park-installed (S5-5 form), so a failure here can never strand an
 * unconfined agent: the agent is either parked or started in proven coarse
 * mode, and the outcome is never silently green.
 */
export async function runExclusiveEgressArming(
  ctx: { agentUid: number },
  ops: ExclusiveEgressArmOps,
): Promise<ExclusiveEgressArmOutcome> {
  let committed: ExclusiveGenerationIdentity;
  try {
    committed = await ops.bringUpGeneration();
  } catch (err) {
    return degradeLoud(ctx, ops, "bring-up", (err as Error).message);
  }
  if (committed.agent_uid !== ctx.agentUid) {
    // Identity keying: a commit for a different uid must never release THIS
    // agent, and must never be blessed by this stage's outcome.
    return degradeLoud(
      ctx,
      ops,
      "bring-up",
      `generation bring-up committed uid ${committed.agent_uid}, expected ${ctx.agentUid} (cross-uid commit refused)`,
    );
  }
  ops.print(
    `Exclusive-egress generation ${committed.generation_id} committed for uid ${ctx.agentUid} ` +
      `(gate port ${committed.gate_port}); releasing the parked harness through the barrier.`,
  );

  let release: ReleaseBarrierOutcome;
  try {
    release = await ops.runReleaseSequence(committed);
  } catch (err) {
    // The barrier's contract is discriminated outcomes, but a throwing op
    // wiring must still fail closed here: treat as a parked release failure.
    return degradeLoud(ctx, ops, "release", `release sequence threw: ${(err as Error).message}`);
  }

  if (release.kind === "released") {
    await ops.audit(EXCLUSIVE_EGRESS_ARMED_AUDIT_OP, {
      agent_uid: ctx.agentUid,
      generation_id: committed.generation_id,
      gate_port: committed.gate_port,
    });
    return { kind: "exclusive-armed", generationId: committed.generation_id };
  }
  if (release.kind === "released-repark-failed") {
    // Running + confined, but the boot path is not re-parked: DISTINCT amber,
    // never green, never silently degraded.
    await ops.audit(EXCLUSIVE_EGRESS_ARMED_AUDIT_OP, {
      agent_uid: ctx.agentUid,
      generation_id: committed.generation_id,
      gate_port: committed.gate_port,
      repark_failed: release.reparkError,
    });
    return {
      kind: "exclusive-armed-repark-failed",
      generationId: committed.generation_id,
      reparkError: release.reparkError,
    };
  }
  // Parked: the barrier refused to release (and asserts hold-file/disable
  // state in its outcome). Degrade loud; carry any cleanup errors forward.
  return degradeLoud(
    ctx,
    ops,
    "release",
    `release barrier parked at stage ${release.stage}: ${release.reason}`,
    release.cleanupErrors,
  );
}

/**
 * The degrade-loud path (design answer 2, choice (b), posture-conditioned on
 * S5-P which is on main): keep the proven coarse wall armed, restore the
 * manifest to coarse scope through the AUDITED S5-4 coarse-only composition,
 * start the harness in coarse mode, and return the distinct non-green
 * outcome. Every sub-step failure degrades further toward agent-not-running
 * (never toward unconfined or silently green) and stays in the outcome.
 */
async function degradeLoud(
  ctx: { agentUid: number },
  ops: ExclusiveEgressArmOps,
  stage: "bring-up" | "release",
  reason: string,
  cleanupErrors: string[] = [],
): Promise<ExclusiveEgressArmOutcome> {
  const errors = [...cleanupErrors];
  let coarseCompositionRestored = false;
  try {
    await ops.restoreCoarseComposition(reason);
    coarseCompositionRestored = true;
  } catch (err) {
    errors.push(`coarse composition restore failed: ${(err as Error).message}`);
  }
  let harness: HarnessDisposition | undefined;
  if (coarseCompositionRestored) {
    // Only start the agent over a manifest that is PROVEN back in coarse
    // (agent-reachable) scope; starting it over exclusive-scoped rules with
    // no live gate would confine it into silence.
    try {
      await ops.startHarnessCoarse();
      harness = startedCoarseDisposition();
    } catch (err) {
      errors.push(
        `coarse harness start failed (this run did not start the agent): ${(err as Error).message}`,
      );
    }
  }
  if (harness === undefined) {
    // FIX-ROUND 4, the round's whole point. Reaching here means one of two
    // things about THIS RUN -- the coarse restore failed, or the coarse start
    // failed -- and NEITHER is a fact about whether a process is alive. The
    // most common way to reach here is the release barrier refusing precisely
    // BECAUSE a live process survived the bootout, in which case the agent is
    // demonstrably up. So ask, do not infer.
    harness = { disposition: "not-started", claim: await ops.assessHarnessParked() };
  }
  // The audit record carries the CLAIM, not a boolean: a posture surface or
  // SIEM consumer reading `harness_started_coarse: false` used to receive the
  // documented meaning "the agent is parked" with no pid information at all,
  // which made the falsehood SILENT downstream rather than merely
  // self-contradictory in the operator prose.
  const harnessAudit =
    harness.disposition === "started-coarse"
      ? { harness_run_state: "running-coarse", harness_run_state_basis: harness.observed }
      : { harness_run_state: harness.claim.state, harness_run_state_basis: harness.claim.sentence };
  await ops.audit(EXCLUSIVE_EGRESS_DEGRADED_AUDIT_OP, {
    agent_uid: ctx.agentUid,
    stage,
    reason,
    coarse_composition_restored: coarseCompositionRestored,
    harness_disposition: harness.disposition,
    ...harnessAudit,
    cleanup_errors: errors,
  });
  ops.print(
    `Exclusive egress could NOT come live (${stage}): ${reason}. ` +
      (coarseCompositionRestored
        ? "The coarse Castle Wall remains armed and the manifest is back in coarse scope (a distinct NON-GREEN state on every posture surface). "
        : "The manifest could NOT be restored to coarse scope. ") +
      // The ONE sentence about run state, and it comes from the chokepoint.
      harnessDispositionSentence(harness) +
      " Fix with: sudo sanctuary protect --repair-egress-gate",
  );
  return {
    kind: "degraded-coarse-active",
    stage,
    reason,
    coarseCompositionRestored,
    harness,
    cleanupErrors: errors,
  };
}

// ---------------------------------------------------------------------------
// Repair verb (`sudo sanctuary protect --repair-egress-gate`, design MED-7)
// ---------------------------------------------------------------------------

/** Context for {@link runEgressGateRepair}. */
export interface EgressGateRepairContext {
  agentUid: number;
  /** Whether stdin is a TTY. The override flag REFUSES without one. */
  isTty: boolean;
  /** `--override-transient-pf-rules` was passed (TTY-only, audited). */
  overrideTransientPfRules: boolean;
}

/** Injected side effects for the repair sequence. */
export interface EgressGateRepairOps {
  /**
   * The MED-7 drift guard: diff the RUNNING pf main ruleset against the
   * base-config-derived ruleset and return the foreign transient rules a
   * third party (VPN, corporate firewall) added without persisting. Throws
   * when the diff itself cannot be computed (the repair then REFUSES --
   * never hook-install blind).
   */
  diffTransientPfRules(): Promise<{ foreign: string[] }>;
  /**
   * PARK the harness before any repair mutation (fix-round BLOCKER-3 +
   * fix-round-2 HIGH-2): a degrade-loud outcome may have left the harness
   * RUNNING IN COARSE MODE, and the bring-up republishes the manifest
   * exclusive-scoped -- doing that under a live coarse harness would confine
   * it into silence mid-flight. "Park" is the FULL PERSISTENT parked state,
   * not just not-running-now: production runs `launchctl bootout`
   * (not-running is success) + `launchctl disable` + hold-file removal +
   * parked-plist restore, captures each result, and VERIFIES the whole
   * posture (not running + job disabled in launchd's override db + hold file
   * absent + parked plist on disk). Without the last three, a "parked" claim
   * can leave stale release material that boots the harness at the next
   * reboot. MUST throw (enumerating every failed step) unless the full
   * parked state is verified.
   */
  parkHarness(): Promise<void>;
  /**
   * Verify the FULL persistent parked posture (fix-round-2 HIGH-2): the
   * harness process is not running, the launchd job is disabled in the
   * override database, the per-uid hold file is absent, and the on-disk
   * plist is the parked barrier form (or absent). Discriminated, never
   * throws in spirit (a throwing impl is treated as not-verified). Used
   * before any `repair-failed` outcome claims the agent is parked: a
   * stopped-but-releasable harness (enable override left on, released plist
   * + hold file still on disk) is NOT parked -- it can boot at next reboot.
   */
  verifyParkedPersistent(): Promise<{ ok: true } | { ok: false; problems: string[] }>;
  /**
   * The coded recovery path for a QUARANTINED committed registry entry
   * (fix-round-4 P2). A malformed committed entry marks the registry dirty
   * (correct, fail-closed: tokens are withheld host-wide), but every registry
   * MUTATION the rest of this sequence performs normalizes wholesale and
   * THROWS on that same entry -- so without this step the documented repair
   * verb failed before it could rewrite anything (permanent host-wide token
   * denial until manual registry surgery). Production (root-only, locked):
   * captures each quarantined entry's raw content to a forensic sidecar
   * FIRST, then removes it (or keeps the uid as a block-only tombstone when
   * its uid/port/fortress still validate -- never dropping live block rules),
   * re-renders + re-arms the union from the remaining valid entries, and
   * persists clean. Acts ONLY on entries the quarantine listing classifies as
   * malformed; transiently-invalid state (missing enable token, journaled
   * pending) never drops an entry. No-op when nothing is quarantined. Throws
   * on failure (the repair then fails at the distinct `quarantine-repair`
   * stage with the registry untouched).
   */
  repairQuarantinedRegistry(): Promise<PfAnchorQuarantineRepairResult>;
  /**
   * Recover any in-flight (uncommitted) generation first (production: the
   * S5-2 `GenerationCoordinator.recover` -- discard/tombstone per the crash
   * table). Throws on failure.
   */
  recoverGeneration(): Promise<void>;
  /** Same as {@link ExclusiveEgressArmOps.bringUpGeneration}. */
  bringUpGeneration(): Promise<ExclusiveGenerationIdentity>;
  /** Same as {@link ExclusiveEgressArmOps.runReleaseSequence}. */
  runReleaseSequence(committed: ExclusiveGenerationIdentity): Promise<ReleaseBarrierOutcome>;
  /** Best-effort audit (distinct local ops). MUST never throw. */
  audit(operation: string, details: Record<string, unknown>): Promise<void>;
  print(line: string): void;
}

/** Terminal outcome of one repair run. */
export type EgressGateRepairOutcome =
  | { kind: "repaired"; generationId: number }
  | { kind: "repaired-repark-failed"; generationId: number; reparkError: string }
  /**
   * The drift guard found foreign transient pf rules and no override was
   * given: automatic repair REFUSES (silently replacing a VPN's rules while
   * reporting ourselves green is the exact MED-7 defect). Posture stays
   * amber; the outcome names the foreign rules and the override flag.
   */
  | { kind: "refused-foreign-transient-rules"; foreign: string[] }
  /** `--override-transient-pf-rules` without an interactive TTY: refused. */
  | { kind: "refused-non-tty-override" }
  /** The drift diff itself failed: refuse rather than hook-install blind. */
  | { kind: "refused-diff-unavailable"; reason: string }
  /**
   * The repair ran but could not bring the generation live. The agent's
   * parked claim is HONEST (fix-round BLOCKER-3, tightened by fix-round-2
   * HIGH-2): `parkedStateVerified` is true only when a probe confirmed the
   * FULL persistent parked posture (not running + job disabled + hold file
   * absent + parked plist). False means "the agent may be startable now or
   * at the next boot"; `parkedStateProblems` enumerates exactly which
   * checks failed so the operator knows what release material remains.
   */
  | {
      kind: "repair-failed";
      stage: "park" | "quarantine-repair" | "recover" | "bring-up" | "release";
      reason: string;
      parkedStateVerified: boolean;
      parkedStateProblems: string[];
    };

/**
 * Run the egress-gate repair sequence (design answer 3, the MED-7 guard):
 * drift-check first (refuse on foreign transient rules without an explicit
 * interactive override; the override itself is audited BEFORE any mutation),
 * then PARK the possibly-live harness (fix-round BLOCKER-3: a degrade-loud
 * outcome may have started it in coarse mode; bring-up must never republish
 * the manifest exclusive-scoped under a live coarse harness), then recover
 * -> bring-up -> release. Every failure leaves the agent parked (the
 * barrier's fail-closed park) and reports the stage, and a `repair-failed`
 * outcome claims PARKED only with the FULL persistent parked posture
 * verified (not running + job disabled + hold file absent + parked plist);
 * nothing here can silently clobber third-party pf state or report green
 * without the barrier's released outcome.
 */
export async function runEgressGateRepair(
  ctx: EgressGateRepairContext,
  ops: EgressGateRepairOps,
): Promise<EgressGateRepairOutcome> {
  // Honest-park helper for every repair-failed return (BLOCKER-3, tightened
  // by fix-round-2 HIGH-2): the outcome may claim the agent is parked ONLY
  // when a probe verified the FULL persistent parked posture (not running +
  // job disabled + hold file absent + parked plist); a throwing probe reads
  // as not-verified with the throw enumerated.
  const failParked = async (
    stage: "park" | "quarantine-repair" | "recover" | "bring-up" | "release",
    reason: string,
  ): Promise<EgressGateRepairOutcome> => {
    let parked: { ok: true } | { ok: false; problems: string[] };
    try {
      parked = await ops.verifyParkedPersistent();
    } catch (err) {
      parked = { ok: false, problems: [`parked-state verify probe threw: ${(err as Error).message}`] };
    }
    return {
      kind: "repair-failed",
      stage,
      reason,
      parkedStateVerified: parked.ok,
      parkedStateProblems: parked.ok ? [] : parked.problems,
    };
  };
  // Override is TTY-ONLY (design: "interactive TTY only"): a non-interactive
  // override could be baked into automation and silently clobber VPN rules on
  // every boot, which is exactly what the guard exists to prevent.
  if (ctx.overrideTransientPfRules && !ctx.isTty) {
    ops.print(
      "--override-transient-pf-rules requires an interactive terminal (TTY): the override " +
        "replaces third-party transient pf rules and must be a deliberate, present-operator choice.",
    );
    return { kind: "refused-non-tty-override" };
  }

  let foreign: string[];
  try {
    foreign = (await ops.diffTransientPfRules()).foreign;
  } catch (err) {
    const reason = (err as Error).message;
    await ops.audit(EGRESS_GATE_REPAIR_REFUSED_AUDIT_OP, {
      agent_uid: ctx.agentUid,
      reason: `transient-rule diff unavailable: ${reason}`,
    });
    ops.print(
      `Repair refused: could not diff the running pf ruleset against the base config (${reason}); ` +
        "refusing to reload the main ruleset blind.",
    );
    return { kind: "refused-diff-unavailable", reason };
  }

  if (foreign.length > 0) {
    if (!ctx.overrideTransientPfRules) {
      await ops.audit(EGRESS_GATE_REPAIR_REFUSED_AUDIT_OP, {
        agent_uid: ctx.agentUid,
        reason: "foreign transient pf rules present",
        foreign_rules: foreign,
      });
      ops.print(
        `Repair refused: ${foreign.length} pf rule(s) in the running ruleset are not in the base ` +
          `config (likely a VPN or firewall tool): ${foreign.join(" | ")}. Re-arming would replace ` +
          "them. Re-run with --override-transient-pf-rules to proceed anyway (interactive only), " +
          "or persist those rules into /etc/pf.conf first.",
      );
      return { kind: "refused-foreign-transient-rules", foreign };
    }
    // Audit the override BEFORE any mutation; the override never proceeds
    // unaudited (an audit failure here must not be silent -- audit() is
    // best-effort by contract, so also print loudly).
    await ops.audit(EGRESS_GATE_REPAIR_OVERRIDE_AUDIT_OP, {
      agent_uid: ctx.agentUid,
      foreign_rules: foreign,
    });
    ops.print(
      `OVERRIDE: proceeding despite ${foreign.length} foreign transient pf rule(s); they will be ` +
        "replaced by the base-config-derived ruleset. This override is recorded in the audit log.",
    );
  }

  // Stage: park (BLOCKER-3). The bring-up below republishes the manifest
  // exclusive-scoped and tears down / re-creates gate surfaces; the harness
  // (possibly running in coarse mode after a prior degrade) must be VERIFIED
  // stopped first. parkHarness throws unless the stop is verified.
  try {
    await ops.parkHarness();
  } catch (err) {
    return failParked("park", `could not park the harness before repair: ${(err as Error).message}`);
  }

  // Stage: quarantine-repair (fix-round-4 P2). MUST run before any other
  // registry mutation: a quarantined (structurally malformed) committed entry
  // makes every wholesale-normalizing mutation below throw, so without this
  // coded path the repair verb the dirty-registry log lines point at could
  // never rewrite anything -- host-wide token denial until manual surgery.
  // The verb is a no-op when nothing is quarantined, acts ONLY on entries the
  // quarantine listing classifies as malformed (transiently-invalid state is
  // never grounds to drop an entry), and preserves each removed entry's raw
  // content in a forensic sidecar before touching it.
  try {
    const quarantine = await ops.repairQuarantinedRegistry();
    if (quarantine.repaired) {
      await ops.audit(EGRESS_GATE_REPAIR_QUARANTINE_AUDIT_OP, {
        agent_uid: ctx.agentUid,
        forensic_path: quarantine.forensicPath,
        quarantined: quarantine.findings.map((f) => ({
          index: f.index,
          reason: f.reason,
          agent_uid: f.agent_uid,
          disposition: f.disposition,
          // Fix-round-5 P1: a removed structurally VALID duplicate is loud in
          // the audit record too (kept vs removed generation).
          ...(f.duplicate !== undefined ? { duplicate: f.duplicate } : {}),
        })),
        // Fix-round-6 F1: a repaired malformed generation floor is loud in the
        // audit record (raw evidence, best-effort parse, resolved floor).
        ...(quarantine.floorRepair !== undefined
          ? { generation_floor_repair: quarantine.floorRepair }
          : {}),
      });
      for (const f of quarantine.findings) {
        const uidText = f.agent_uid !== null ? `uid ${f.agent_uid}` : "an unrecoverable uid";
        const dispositionText =
          f.disposition === "tombstoned"
            ? "TOMBSTONED block-only (the uid stays packet-confined; its gate channel is gone)"
            : "REMOVED from the committed set";
        // Fix-round-5 P1: removing a structurally VALID duplicate must be loud
        // -- name the uid and both generations, and say what protects the
        // discarded id from reuse (the persisted generation floor).
        const duplicateText =
          f.duplicate !== undefined
            ? ` This entry was a structurally VALID DUPLICATE of a kept entry for the same uid ` +
              `(kept generation ${f.duplicate.kept_generation_id ?? "none"}, removed generation ` +
              `${f.duplicate.removed_generation_id ?? "none"}).` +
              (f.duplicate.removed_generation_id !== null
                ? " The removed generation was folded into the registry's persisted generation " +
                  "floor so it can never be reallocated."
                : "")
            : "";
        ops.print(
          `Quarantined registry entry #${f.index} (${uidText}) was ${dispositionText}: ${f.reason}.` +
            duplicateText +
            ` Raw entry preserved for forensics at ${quarantine.forensicPath}. The affected agent ` +
            "must be RE-PROVISIONED (sudo sanctuary protect) before its gate can serve again.",
        );
      }
      // Fix-round-6 F1: a repaired malformed generation floor is LOUD --
      // especially the unrecoverable case, where the reset floor is only "the
      // maximum generation still observable" and the original may have been
      // higher.
      if (quarantine.floorRepair !== undefined) {
        const fr = quarantine.floorRepair;
        ops.print(
          fr.unrecoverable
            ? "The registry's persisted generation floor was malformed and its original value is " +
                `UNRECOVERABLE (raw ${JSON.stringify(fr.raw)} did not parse as a number). The floor ` +
                "was reset to the maximum generation still observable across committed entries and " +
                `tombstones (${fr.resolved_floor ?? "none observable; no floor persisted"}). The ` +
                "original floor may have been higher, so RE-PROVISIONING the confined agents " +
                "(sudo sanctuary protect) is advised: it allocates a fresh generation above " +
                "everything observable, so no stale generation artifact can masquerade as current. " +
                `Pre-repair bytes preserved at ${quarantine.forensicPath}.`
            : "The registry's persisted generation floor was malformed; its preserved raw value " +
                `${JSON.stringify(fr.raw)} parsed to ${fr.parsed} and was folded into the repaired ` +
                `floor (${fr.resolved_floor}). Pre-repair bytes preserved at ${quarantine.forensicPath}.`,
        );
      }
    }
  } catch (err) {
    return failParked(
      "quarantine-repair",
      `quarantined-registry repair failed (registry left untouched, still dirty): ${(err as Error).message}`,
    );
  }

  try {
    await ops.recoverGeneration();
  } catch (err) {
    return failParked("recover", (err as Error).message);
  }
  let committed: ExclusiveGenerationIdentity;
  try {
    committed = await ops.bringUpGeneration();
  } catch (err) {
    return failParked("bring-up", (err as Error).message);
  }
  let release: ReleaseBarrierOutcome;
  try {
    release = await ops.runReleaseSequence(committed);
  } catch (err) {
    return failParked("release", (err as Error).message);
  }
  if (release.kind === "released") {
    await ops.audit(EGRESS_GATE_REPAIR_AUDIT_OP, {
      agent_uid: ctx.agentUid,
      generation_id: committed.generation_id,
      override_used: ctx.overrideTransientPfRules && foreign.length > 0,
    });
    return { kind: "repaired", generationId: committed.generation_id };
  }
  if (release.kind === "released-repark-failed") {
    await ops.audit(EGRESS_GATE_REPAIR_AUDIT_OP, {
      agent_uid: ctx.agentUid,
      generation_id: committed.generation_id,
      repark_failed: release.reparkError,
    });
    return {
      kind: "repaired-repark-failed",
      generationId: committed.generation_id,
      reparkError: release.reparkError,
    };
  }
  return failParked("release", `release barrier parked at stage ${release.stage}: ${release.reason}`);
}

// ---------------------------------------------------------------------------
// Boot release sequence (design "Boot ordering via the root supervisor")
// ---------------------------------------------------------------------------

/** One confined agent the boot daemon must re-release. */
export interface BootReleaseAgent {
  agent_uid: number;
}

/**
 * Per-agent boot result (the boot daemon logs these; it never throws).
 *
 * HONESTY CONTRACT (fix-round-2 BLOCKER-1): `parked` is claimed ONLY when
 * the re-park ops actually ran, and it carries their REAL results
 * (`holdFileRemoved`/`jobDisabled`/`cleanupErrors` from the barrier or the
 * contextless re-park). A release attempt that THREW proves nothing about
 * the parked state and maps to the DISTINCT `park-not-verified` kind --
 * never a synthetic "parked" nobody verified.
 */
export interface BootReleaseResult {
  agent_uid: number;
  outcome:
    | { kind: "released"; generationId: number }
    | { kind: "released-repark-failed"; generationId: number; reparkError: string }
    | {
        kind: "parked";
        reason: string;
        /** True when the hold file is confirmed absent (real op result). */
        holdFileRemoved: boolean;
        /** True when the launchd job is confirmed disabled (real op result). */
        jobDisabled: boolean;
        /** Re-park op failures, LOUD and per-op (empty on a clean park). */
        cleanupErrors: string[];
        /**
         * The barrier's run-state claim (fix-round 4). `kind: "parked"` here
         * means the barrier did not release; only `parkedClaim.state ===
         * "parked"` means a process is known to be gone.
         */
        parkedClaim: ParkedClaim;
      }
    | {
        kind: "park-not-verified";
        /** Why no verified park exists (e.g. the release attempt threw). */
        reason: string;
      };
}

/**
 * The boot daemon's exclusive-egress sequence: for every confined agent in
 * the S5-1 registry, run the S5-5 release barrier (whose boot ops re-arm the
 * pf anchor union from the registry, verify the gate + generation, rebind or
 * coordinate a new generation, and only then enable+bootstrap the harness).
 * PER-AGENT FAIL-CLOSED: one agent's failure leaves THAT agent parked (loud,
 * amber -- the design's "agent may be down after boot" trade) and never blocks
 * or releases another. This function NEVER throws: the boot daemon must keep
 * serving policy regardless.
 */
export async function runBootExclusiveEgressRelease(
  agents: readonly BootReleaseAgent[],
  ops: {
    /** Run the full S5-5 release sequence for one agent (boot ops). */
    releaseAgent(agentUid: number): Promise<ReleaseBarrierOutcome>;
    /** Best-effort audit; never throws. */
    audit(operation: string, details: Record<string, unknown>): Promise<void>;
    print(line: string): void;
  },
): Promise<BootReleaseResult[]> {
  const results: BootReleaseResult[] = [];
  for (const agent of agents) {
    let outcome: BootReleaseResult["outcome"];
    try {
      const release = await ops.releaseAgent(agent.agent_uid);
      if (release.kind === "released") {
        outcome = { kind: "released", generationId: release.generation_id };
      } else if (release.kind === "released-repark-failed") {
        outcome = {
          kind: "released-repark-failed",
          generationId: release.generation_id,
          reparkError: release.reparkError,
        };
      } else {
        // Carry the REAL re-park results forward (fix-round-2 BLOCKER-1):
        // "parked" without the op results would be a claim nobody could audit.
        outcome = {
          kind: "parked",
          reason: `release barrier parked at stage ${release.stage}: ${release.reason}`,
          holdFileRemoved: release.holdFileRemoved,
          jobDisabled: release.jobDisabled,
          cleanupErrors: release.cleanupErrors,
          parkedClaim: release.parkedClaim,
        };
      }
    } catch (err) {
      // Fix-round-2 BLOCKER-1: a THROW out of the release attempt proves
      // nothing about the parked state (the pre-fix code reported a synthetic
      // PARKED here with no re-park op verified). Distinct, LOUD, honest.
      outcome = {
        kind: "park-not-verified",
        reason: `boot release threw before a verified park: ${(err as Error).message}`,
      };
    }
    if (outcome.kind === "park-not-verified") {
      ops.print(
        `[castle-wall] boot: uid ${agent.agent_uid} exclusive egress NOT live AND the parked state ` +
          `was NOT verified (${outcome.reason}); treat the agent as possibly startable and ` +
          "intervene manually. Fix with: sudo sanctuary protect --repair-egress-gate",
      );
    } else if (outcome.kind === "parked") {
      // Fix-round 4: the run-state sentence is the CHOKEPOINT's, not this
      // function's. It used to hardcode "remains PARKED (fail-closed)" from
      // the outcome kind alone, which names only the fact that the barrier
      // did not release.
      ops.print(
        `[castle-wall] boot: uid ${agent.agent_uid} exclusive egress NOT live: ${outcome.reason}. ` +
          outcome.parkedClaim.sentence +
          (outcome.cleanupErrors.length > 0
            ? ` WARNING: re-park ops reported failures (hold file removed: ${outcome.holdFileRemoved}, ` +
              `job disabled: ${outcome.jobDisabled}): ${outcome.cleanupErrors.join("; ")}.`
            : "") +
          " Fix with: sudo sanctuary protect --repair-egress-gate",
      );
    } else {
      ops.print(
        `[castle-wall] boot: uid ${agent.agent_uid} exclusive egress re-armed ` +
          `(generation ${outcome.generationId})` +
          (outcome.kind === "released-repark-failed"
            ? ` -- WARNING: boot-state re-park failed (${outcome.reparkError}); next boot may auto-start pre-G5`
            : ""),
      );
    }
    await ops.audit("exclusive_egress_boot_release", {
      agent_uid: agent.agent_uid,
      outcome: outcome.kind,
      ...(outcome.kind === "released" || outcome.kind === "released-repark-failed"
        ? { generation_id: outcome.generationId }
        : { reason: outcome.reason }),
      ...(outcome.kind === "parked"
        ? {
            hold_file_removed: outcome.holdFileRemoved,
            job_disabled: outcome.jobDisabled,
            cleanup_errors: outcome.cleanupErrors,
          }
        : {}),
    });
    results.push({ agent_uid: agent.agent_uid, outcome });
  }
  return results;
}
