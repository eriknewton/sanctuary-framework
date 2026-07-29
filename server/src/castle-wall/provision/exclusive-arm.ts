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
  parkedClaimAuditFields,
  startedCoarseDisposition,
  type HarnessDisposition,
  type ParkedClaim,
} from "../../egress-gate/parked-claim.js";
import {
  EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE,
  EGRESS_GATE_STAND_DOWN_EFFECT,
  EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_COMMAND,
} from "../../egress-gate/operator-advice.js";
import { observing, type Observed } from "../../claim-witness.js";

/** Distinct local audit operation strings (never a widened shared enum). */
export const EXCLUSIVE_EGRESS_ARMED_AUDIT_OP = "exclusive_egress_armed";
export const EXCLUSIVE_EGRESS_DEGRADED_AUDIT_OP = "exclusive_egress_degraded_coarse_active";
/**
 * D8 self-heal (2026-07-22): the reconcile preflight removed an ORPHANED
 * exclusive-routing marker left by a hard-interrupted prior arm. Distinct op
 * so a fleet operator can prove the self-heal fired and inspect why the marker
 * was judged orphaned (never a silent mutation -- non-negotiable invariant 3).
 */
export const EXCLUSIVE_ROUTING_STALE_MARKER_RECONCILED_AUDIT_OP =
  "exclusive_routing_stale_marker_reconciled";
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
 * What the exclusive-routing residue gate OBSERVED on disk, and -- on a
 * `"clear"` intent -- what it did about it. The ONE caller is the
 * mode-independent gate `ProvisionFlowOps.reconcileExclusiveRoutingResidue`
 * in `orchestrate.ts` (plus the no-account teardown fallback the
 * `--unprotect-egress-gate` verb uses).
 *
 * FIX F-COARSE-AFTER-EXCLUSIVE (class half, 2026-07-26): this type used to
 * belong to an op on {@link ExclusiveEgressArmOps}, which is wired ONLY when
 * exclusive-egress mode is declared. That is why the self-heal never ran on
 * the plain COARSE run that hit the defect. The reconcile now hangs off the
 * mode-independent flow ops instead; the type stays here because the coarse
 * restore it shares its removal pair with lives in this stage.
 *
 * FIX F4 (adversarial review, 2026-07-26): this WAS `{ reconciled: boolean;
 * reason?: string }`, i.e. two fields that can disagree -- a wiring that kept
 * a marker but forgot the `reason` read as "nothing there" and the run walked
 * into the wedge. That is the same shape #1006 deleted at the park boundary.
 * The union is now TOTAL at the op boundary: "kept" cannot be spelled by
 * omission, and each keep carries the reason its own operator sentence needs.
 *
 * FIX F1/F2 (adversarial review, 2026-07-26): `orphaned` is separate from
 * `reconciled` because the JUDGEMENT and the irreversible REMOVAL are now two
 * steps: the flow judges before the operator confirm (so it never asks anyone
 * to confirm a doomed run) and removes only after the confirm has said yes.
 */
export type ExclusiveRoutingResidue =
  /** No marker on disk. Coarse composition; the run may proceed. */
  | { kind: "clear" }
  /**
   * A marker is present and PROVABLY orphaned (no registry entry, no serving
   * gate, no gate plist), and this call was an `"observe"`: it has NOT been
   * removed. The caller may remove it with a second `"clear"` call once every
   * step that can still say no has said yes.
   */
  | { kind: "orphaned"; detail: string }
  /** A provably-orphaned marker WAS removed by this call. The run may proceed. */
  | { kind: "reconciled"; detail: string }
  /**
   * A marker is present and confinement for its uid looks LIVE (a committed or
   * mid-bring-up S5-1 registry entry, or an owner-verified gate daemon serving
   * the recorded port). This is not residue: a re-run cannot compose over it.
   */
  | { kind: "kept-live"; reason: string }
  /**
   * A marker is present and could NOT be shown to be stale (dirty or
   * quarantined registry, unreadable/unparseable gate runtime state, a
   * surviving gate plist, a cross-uid marker). Fail toward confinement: KEEP.
   */
  | { kind: "kept-uncertain"; reason: string }
  /**
   * A marker is present but this run resolved NO agent uid to scope it
   * against, so guard 0 has no subject and a reconcile would be a cross-uid
   * reconcile. Distinct from `kept-uncertain` because it is the one keep whose
   * subject account may be gone entirely, and so needs its own way out.
   */
  | { kind: "kept-unknown-subject"; reason: string; markerAgentUid: number }
  /**
   * The residue check could not complete. The run must REFUSE, fail-closed:
   * "could not look" is never "nothing there".
   *
   * FIX G8 (re-gate, 2026-07-26): `source` exists because this verdict is
   * produced by ANY throw out of the op, and the operator sentence used to
   * assert the MARKER was at fault on every one of them. `"marker"` is the
   * load contract firing on a present-but-unreadable/malformed marker (the
   * remedy that removes the marker without parsing it is on point).
   * `"residue-check"` is some OTHER surface the check reads throwing -- a
   * malformed anchor registry, for instance -- where the marker's own
   * readability is UNKNOWN and removing it fixes nothing.
   */
  | { kind: "unreadable"; detail: string; source: "marker" | "residue-check" }
  /**
   * FIX G5 (re-gate, 2026-07-26): a `"clear"` intent ran the removal half and
   * it FAILED PART WAY. `removed` names, in order, what this call actually did
   * delete before the failure, so the refusal sentence can state what changed
   * on the fortress instead of asserting that nothing did. The pre-fix code
   * let the second `removeFile`'s throw propagate, which rendered "no Castle
   * Wall change was made by this run" over a fortress that had just been put
   * back on coarse composition.
   */
  | { kind: "removal-failed"; detail: string; removed: string[] };

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
  | { kind: "exclusive-armed"; generationId: Observed<number> }
  /**
   * Live but AMBER: the harness is running confined, but the persistent boot
   * state could not be re-parked (next boot could auto-start pre-G5). Never
   * rendered green; the repair verb re-runs the re-park.
   */
  | { kind: "exclusive-armed-repark-failed"; generationId: Observed<number>; reparkError: string }
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
      coarseCompositionRestored: Observed<boolean>;
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
    return {
      kind: "exclusive-armed",
      generationId: await observing(
        "provision-exclusive-arm.exclusive-armed",
        () => committed.generation_id,
      ),
    };
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
      generationId: await observing(
        "provision-exclusive-arm.exclusive-armed",
        () => committed.generation_id,
      ),
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
  const coarseCompositionRestored = await observing(
    "provision-exclusive-arm.coarse-composition-restored",
    async () => {
      try {
        await ops.restoreCoarseComposition(reason);
        return true;
      } catch (err) {
        errors.push(`coarse composition restore failed: ${(err as Error).message}`);
        return false;
      }
    },
  );
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
      : parkedClaimAuditFields(harness.claim);
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
        : // FIX F-COARSE-AFTER-EXCLUSIVE: an unrestored coarse composition
          // means the fortress is STILL in exclusive routing composition, and
          // in that state the plain coarse arm path is refused -- so "re-run
          // the repair" (below) is not by itself a way out. Name the product
          // path that provably clears it.
          "The manifest could NOT be restored to coarse scope, so the fortress is STILL in EXCLUSIVE " +
          "routing composition: a plain 'sudo sanctuary protect --hermes' will be REFUSED until it is " +
          `cleared with '${EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_COMMAND}' (${EGRESS_GATE_STAND_DOWN_EFFECT}). `) +
      // The ONE sentence about run state, and it comes from the chokepoint.
      harnessDispositionSentence(harness) +
      ` Fix with: ${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE}`,
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
// Repair verb (`sudo sanctuary protect --repair-egress-gate --stand-down-agent`, design MED-7)
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
  /**
   * Same as {@link ExclusiveEgressArmOps.restoreCoarseComposition}: the AUDITED
   * S5-4 coarse-only restore (gate daemons down, exclusive marker + gate policy
   * removed, registry entry + credential + token torn down, endpoint rules
   * republished agent-scoped, composition verified residue-free).
   *
   * FIX F-COARSE-AFTER-EXCLUSIVE (HIGH, Mini1 re-drill 2026-07-26). The arm
   * path already degraded to coarse on every failure; the REPAIR path did not.
   * So a repair whose bring-up committed a generation and whose release then
   * failed left the fortress in EXCLUSIVE routing composition with the agent
   * parked -- and the next plain `sudo sanctuary protect --hermes`, a command
   * that had worked 25 minutes earlier, was refused by the exclusive
   * composition invariant ("agent-reachable direct endpoint allow(s) survived
   * composition"). Nothing in the product cleared that except the operator
   * knowing to run `--unprotect-egress-gate`. A failed repair must leave the
   * fortress in a composition the coarse path can still arm.
   */
  restoreCoarseComposition(reason: string): Promise<void>;
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
      /**
       * FIX F-COARSE-AFTER-EXCLUSIVE: what the fortress's ROUTING COMPOSITION
       * was left in, so the operator is never told a failed repair is inert
       * when it has actually left the host in a mode that refuses the coarse
       * arm path.
       *
       *  - `"restored"`: the audited coarse-only restore ran and verified; a
       *    plain `sudo sanctuary protect --hermes` will work again.
       *  - `"not-attempted"`: this failure happened BEFORE the bring-up put
       *    the fortress into exclusive composition, so there was nothing this
       *    run needed to undo.
       *  - `"exclusive-left"`: the restore was owed and FAILED. The fortress
       *    is still in exclusive routing composition; the coarse path will be
       *    refused until `--unprotect-egress-gate` clears it. `error` carries
       *    the restore failure.
       */
      coarseComposition: "restored" | "not-attempted" | "exclusive-left";
      /** Present only when `coarseComposition === "exclusive-left"`. */
      coarseRestoreError?: string;
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
    /**
     * FIX F-COARSE-AFTER-EXCLUSIVE: true for the stages that run AFTER the
     * bring-up has put the fortress into exclusive routing composition. Those
     * are exactly the failures that used to strand the host in a mode where
     * the plain coarse arm is refused.
     */
    exclusiveCompositionOwed: boolean,
  ): Promise<EgressGateRepairOutcome> => {
    let coarseComposition: "restored" | "not-attempted" | "exclusive-left" = "not-attempted";
    let coarseRestoreError: string | undefined;
    if (exclusiveCompositionOwed) {
      try {
        await ops.restoreCoarseComposition(reason);
        coarseComposition = "restored";
      } catch (err) {
        coarseComposition = "exclusive-left";
        coarseRestoreError = (err as Error).message;
      }
    }
    // Parked state is probed AFTER the restore: the restore re-publishes the
    // manifest and tears gate surfaces down, so a claim taken before it would
    // describe a host state that no longer exists by the time it is printed.
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
      coarseComposition,
      ...(coarseRestoreError !== undefined ? { coarseRestoreError } : {}),
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
    return failParked("park", `could not park the harness before repair: ${(err as Error).message}`, false);
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
      false,
    );
  }

  try {
    await ops.recoverGeneration();
  } catch (err) {
    return failParked("recover", (err as Error).message, false);
  }
  let committed: ExclusiveGenerationIdentity;
  try {
    committed = await ops.bringUpGeneration();
  } catch (err) {
    return failParked("bring-up", (err as Error).message, true);
  }
  let release: ReleaseBarrierOutcome;
  try {
    release = await ops.runReleaseSequence(committed);
  } catch (err) {
    return failParked("release", (err as Error).message, true);
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
  // FIX F-COARSE-AFTER-EXCLUSIVE: THE drill's actual path. The bring-up
  // committed a generation (fortress now in exclusive composition) and the
  // barrier then refused to release. Pre-fix this returned with the fortress
  // still exclusive, which is what made the next plain coarse arm refuse.
  return failParked("release", `release barrier parked at stage ${release.stage}: ${release.reason}`, true);
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
          `intervene manually. Fix with: ${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE}`,
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
          ` Fix with: ${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE}`,
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
            // FIX-ROUND 5: symmetry with the degrade path's audit. `outcome:
            // "parked"` here means only "the barrier did not release"; the
            // type doc says so, but a SIEM consumer does not read type docs.
            // Without these two fields this record reads as a park over a host
            // where the code had just observed a live pid -- the same
            // downstream-silence gap round 4 closed on `degradeLoud`, left
            // asymmetric. The claim is in the record, not only in the prose.
            ...parkedClaimAuditFields(outcome.parkedClaim),
          }
        : {}),
    });
    results.push({ agent_uid: agent.agent_uid, outcome });
  }
  return results;
}
