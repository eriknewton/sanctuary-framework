/**
 * Exclusive-egress posture object + aggregate-green capping (Unified Protect
 * Slice 5 S5-P, the design's HIGH-3 hard predecessor; design rev3 §6).
 *
 * THE PROBLEM (review HIGH-3). Slice 5's install flow (S5-6, WIRED) has a
 * degrade-loud outcome: fine-grained exclusive egress cannot come live, the
 * proven coarse wall stays armed, and the agent runs "coarse-only". The
 * never-silently-degrade rule (AGENTS.md invariant 5) forbids that state
 * existing ANYWHERE in the tree before every posture surface can render it as
 * a DISTINCT non-green status - otherwise a coarse-only degrade would be an
 * amber line in CLI text while the dashboard, the feature-health row, and the
 * status APIs still show Castle Wall green. This module is that predecessor:
 * the first-class, queryable exclusive-egress posture object, plus the ONE
 * capping rule every surface's green flows through.
 *
 * THE POSTURE OBJECT (design §6, verbatim minimum): per confined agent -
 *   - `manifest_gate_rule_generation` (the generation the published gate
 *     policy carries),
 *   - `pf_liveness` (the FULL reasons vector, never a bare boolean),
 *   - `gate_process` (up + port-owner-verified),
 *   - `generation_match` (pf pass port == manifest port == committed registry
 *     port AND manifest generation == committed generation),
 *   - `mode` (`exclusive` | `coarse-only` | `unprotected`).
 *
 * REAL STATE SURFACES, NOT PARALLEL BOOKKEEPING. The builder consumes the
 * shipped Slice-5 surfaces directly:
 *   - S5-1 (#935): the anchor-registry entry shape (`generation_id` /
 *     `tombstone` additive fields) + the registry `dirty` needs-repair signal,
 *   - S5-2 (#938): {@link resolveCommittedGeneration} (a G3-written entry is
 *     NOT committed while a staging record exists) and
 *     {@link evaluateGenerationMatch} (the three-surface refusal check) - the
 *     SAME functions the gate's serve decision uses, so posture and the gate
 *     can never disagree about what "committed" means,
 *   - S5-3 (#943): {@link PfLivenessResult} - the root liveness oracle's
 *     `verifyLivenessToken` output drops straight in as the `pf_liveness`
 *     probe, so the posture's pf verdict is the gate's own fail-closed verdict
 *     (absent/expired/bad-signature/binding-mismatch all read not-live).
 *
 * MODE SEMANTICS (the design's vocabulary, applied conservatively):
 *   - `exclusive`   - the agent was provisioned fine-grained AND the coarse
 *     wall is armed over it AND every exclusive-stack component is live
 *     (generation match, pf liveness, gate up + owner-verified). The ONLY
 *     state that may contribute to aggregate green.
 *   - `coarse-only` - the coarse wall is armed but the exclusive stack is not
 *     live (either a fine-grained degrade, or an agent only ever provisioned
 *     coarse). A DISTINCT non-green status on every surface.
 *   - `unprotected` - neither. Non-green.
 *
 * AGGREGATE GREEN CAPPING (design §6: "aggregate green REQUIRES
 * exclusive-egress live"). Every posture surface in the tree earns wall-green
 * from ONE builder (`principal-policy/posture.ts:buildCastleWallPosture`,
 * whose `arm_state === "armed"` is the sole green the CLI, the dashboard, the
 * v1.1 console, the hero shield, fortress-view, and /v1/status all consume).
 * {@link exclusiveEgressCapsAggregateGreen} is the one rule that builder
 * applies: when a fine-grained-provisioned agent's exclusive stack is not
 * live, `armed` is capped to the DISTINCT non-green `coarse_only` arm-state,
 * so every surface repaints at once - a chokepoint, not N per-surface checks.
 *
 * FAIL-CLOSED PROVIDER CONTRACT. The live producer is WIRED (S5-6:
 * `egress-gate/arming-wiring.ts` createExclusiveEgressPostureProducer,
 * bound by dashboard-standalone on darwin; drill still owed):
 * surfaces take an OPTIONAL provider. Provider absent = no fine-grained agent
 * has ever been provisioned = no cap (today's honest truth). Provider present
 * but FAILING = we cannot prove exclusive-egress live for a fleet that
 * declared it = cap green ({@link failedExclusiveEgressStatus}); a posture
 * read failure must never render the stronger claim.
 *
 * HONESTY BOUNDS. This is the posture LIBRARY + surface rendering only. It
 * arms nothing, probes nothing by itself (all probe results are injected), and
 * advances no capability claim: the exclusive-egress fine-grained claim stays
 * drill-pending (code; Erik-present drill owed). The `coarse-only` state this
 * module renders is not yet producible by any shipped code path - S5-4 lands
 * the compose-time fallback as an uncalled library and S5-6 wires it - which
 * is exactly the design's ordering constraint: render-first, produce-second.
 */

import type { PfLivenessResult } from "./pf-anchor.js";
import {
  evaluateGenerationMatch,
  resolveCommittedGeneration,
} from "./generation.js";

/**
 * The egress-protection mode a confined agent is actually in. Wire values are
 * design-literal (`coarse-only` hyphenated, as ratified vocabulary).
 */
export type ExclusiveEgressMode = "exclusive" | "coarse-only" | "unprotected";

/** Gate-process component status (up + port-owner-verified, design §6). */
export interface GateProcessStatus {
  /** The gate daemon is up (bound / responding). */
  up: boolean;
  /**
   * Root verified the listener on the committed port is the gate process
   * (pid + start-time; the S5-2 G2 owner-check shape). Anti-squat: a port
   * owned by a different process must never read live.
   */
  port_owner_verified: boolean;
  /** Why not, when not. Empty when up + verified. */
  reasons: string[];
}

/**
 * The registry entry surface the posture reads (the S5-1 `PfAnchorRegistryEntry`
 * projection the generation machine already consumes - `generation_id` and
 * `tombstone` are the S5-2 additive fields).
 */
export interface ExclusiveEgressRegistryEntryView {
  agent_uid: number;
  gate_port: number;
  generation_id?: number;
  tombstone?: boolean;
}

/** Inputs to {@link buildExclusiveEgressPosture}: injected probe RESULTS (host-free). */
export interface ExclusiveEgressPostureInput {
  /** The dedicated agent service-account uid this posture describes. */
  agent_uid: number;
  /**
   * Durable provisioning intent: was this agent provisioned in FINE-GRAINED
   * (exclusive-egress) mode? The cap ("aggregate green requires
   * exclusive-egress live") applies only to fine-grained-provisioned agents;
   * a coarse-only-provisioned agent keeps today's coarse green semantics.
   */
  fine_grained_declared: boolean;
  /**
   * The coarse Castle Wall is armed over this agent (the drill-proven
   * per-uid NEFilter confinement). Injected: the caller derives it from the
   * same evidence surface it already trusts, never from daemon self-report.
   */
  coarse_wall_armed: boolean;
  /** The registry entry for this uid (S5-1 `list()`/`readEntry`), or null. */
  registry_entry: ExclusiveEgressRegistryEntryView | null;
  /** A generation staging record exists for this uid (S5-2: NOT committed). */
  staging_record_present: boolean;
  /** The registry is marked dirty / needs-repair (S5-1: posture MUST read red). */
  registry_dirty: boolean;
  /** The port the LIVE pf pass rule points at, when known. */
  pf_pass_port?: number;
  /** The published generation-bearing gate policy (S5-2 G4), or null. */
  manifest: { gate_port: number; generation_id: number } | null;
  /**
   * The pf-liveness verdict WITH its reasons vector. Production callers pass
   * the S5-3 oracle-token verification result (`verifyLivenessToken` /
   * `createOracleLivenessProbe(...).check()`), which is fail-closed on
   * absent/expired/forged/mismatched tokens by construction.
   */
  pf_liveness: PfLivenessResult;
  /** The gate-process probe result (up + port-owner-verified). */
  gate_process: GateProcessStatus;
}

/**
 * The first-class, queryable exclusive-egress posture object (design §6).
 * Serialized verbatim onto the posture/status APIs; field names are wire.
 */
export interface ExclusiveEgressPosture {
  agent_uid: number;
  /** Durable fine-grained provisioning intent (see the input doc). */
  fine_grained_declared: boolean;
  /** The mode this agent's egress protection is ACTUALLY in. */
  mode: ExclusiveEgressMode;
  /**
   * True iff every exclusive-stack component is live: generation match, pf
   * liveness, gate up + port-owner-verified. NOT sufficient for green on its
   * own - aggregate green composes `castle_wall_armed AND exclusive_egress_live`.
   */
  exclusive_egress_live: boolean;
  /** The generation the published gate policy carries, or null when absent. */
  manifest_gate_rule_generation: number | null;
  /** The full pf-liveness reasons vector (never collapsed to a boolean). */
  pf_liveness: { live: boolean; reasons: string[] };
  /** Gate process up + port-owner-verified. */
  gate_process: GateProcessStatus;
  /** The S5-2 three-surface generation-match verdict (serve/refuse + reasons). */
  generation_match: { serve: boolean; reasons: string[] };
  /** Aggregate "why not exclusive" reasons vector for rendering. Empty when live. */
  reasons: string[];
}

/**
 * The wall-level summary posture surfaces consume: the per-agent posture
 * objects plus the two aggregate facts the capping rule needs. Attached
 * verbatim to `CastleWallPosture.exclusive_egress` so the posture/status APIs
 * expose the full object queryably.
 */
export interface ExclusiveEgressStatus {
  /** True iff at least one agent is fine-grained-provisioned. */
  fine_grained_declared: boolean;
  /**
   * True iff EVERY fine-grained-provisioned agent's mode is `exclusive`.
   * Vacuously true when none is declared (the cap never fires then).
   */
  exclusive_egress_live: boolean;
  /**
   * The WORST mode across fine-grained-declared agents
   * (unprotected < coarse-only < exclusive), or null when none is declared.
   */
  mode: ExclusiveEgressMode | null;
  /** Per-agent posture objects (every agent the producer knows about). */
  agents: ExclusiveEgressPosture[];
  /** Aggregate reasons vector (why the cap fires), for rendering. */
  reasons: string[];
}

/** Severity order for the worst-mode fold (lower = worse). */
const MODE_SEVERITY: Readonly<Record<ExclusiveEgressMode, number>> =
  Object.freeze({
    unprotected: 0,
    "coarse-only": 1,
    exclusive: 2,
  });

/**
 * Build one agent's exclusive-egress posture object from injected probe
 * results. Pure; no I/O. Every component failure surfaces in the reasons
 * vector, and `mode` can read `exclusive` ONLY when the agent is
 * fine-grained-declared, the coarse wall is armed, and every component is
 * live - anything less is `coarse-only` (wall armed) or `unprotected`.
 */
export function buildExclusiveEgressPosture(
  input: ExclusiveEgressPostureInput,
): ExclusiveEgressPosture {
  // S5-2's committed-generation resolver is THE definition of "committed":
  // a staging record in flight, a tombstoned uid, or a dirty registry all
  // resolve to "no committed generation" (never trust a G3-written entry
  // before its G5 commit). Same function the gate's serve decision uses.
  const committed = resolveCommittedGeneration({
    entry: input.registry_entry,
    stagingRecordPresent: input.staging_record_present,
    registryDirty: input.registry_dirty,
  });
  const generationMatch = evaluateGenerationMatch({
    committedGenerationId: committed.committedGenerationId,
    committedPort: committed.committedPort,
    pfPassPort: input.pf_pass_port,
    manifestPort: input.manifest?.gate_port,
    manifestGenerationId: input.manifest?.generation_id,
  });

  const reasons: string[] = [];
  if (!generationMatch.serve) {
    reasons.push(
      ...generationMatch.reasons.map((r) => `generation: ${r}`),
    );
  }
  if (input.pf_liveness.live !== true) {
    const pfReasons = input.pf_liveness.reasons;
    if (pfReasons.length === 0) {
      reasons.push("pf: anchor not live (no reason reported)");
    } else {
      reasons.push(...pfReasons.map((r) => `pf: ${r}`));
    }
  }
  if (!input.gate_process.up) {
    reasons.push("gate: process not up");
  }
  if (!input.gate_process.port_owner_verified) {
    reasons.push("gate: port owner not verified");
  }
  reasons.push(
    ...input.gate_process.reasons.map((r) => `gate: ${r}`),
  );

  const live =
    generationMatch.serve &&
    input.pf_liveness.live === true &&
    input.gate_process.up &&
    input.gate_process.port_owner_verified;

  // Mode: `exclusive` requires the declared intent AND the coarse kernel wall
  // (exclusivity without the kernel default-deny floor would be a hollow
  // claim) AND the live stack. A live stack WITHOUT the declared intent never
  // reads exclusive (no sanctioned path produces that state; refuse to bless
  // it). Anything armed-but-not-exclusive is the DISTINCT `coarse-only`.
  let mode: ExclusiveEgressMode;
  if (input.fine_grained_declared && input.coarse_wall_armed && live) {
    mode = "exclusive";
  } else if (input.coarse_wall_armed) {
    mode = "coarse-only";
  } else {
    mode = "unprotected";
  }
  if (mode !== "exclusive" && input.fine_grained_declared && !input.coarse_wall_armed) {
    reasons.push("wall: coarse Castle Wall not armed over this agent");
  }

  return {
    agent_uid: input.agent_uid,
    fine_grained_declared: input.fine_grained_declared,
    mode,
    exclusive_egress_live: live,
    manifest_gate_rule_generation: input.manifest?.generation_id ?? null,
    pf_liveness: {
      live: input.pf_liveness.live === true,
      reasons: [...input.pf_liveness.reasons],
    },
    gate_process: {
      up: input.gate_process.up,
      port_owner_verified: input.gate_process.port_owner_verified,
      reasons: [...input.gate_process.reasons],
    },
    generation_match: generationMatch,
    reasons,
  };
}

/**
 * Fold per-agent posture objects into the wall-level status the surfaces
 * consume. `exclusive_egress_live` is true iff EVERY fine-grained-declared
 * agent reads `exclusive` (vacuously true when none is declared - the cap
 * never fires for a coarse-only fleet). Pure.
 *
 * PRODUCER CONTRACT (fail-closed, load-bearing): an EMPTY `agents` list means
 * "affirmatively scanned; NO fine-grained agent is provisioned" and correctly
 * does NOT cap green (there is nothing fine-grained to be down). The producer
 * (S5-6) MUST therefore never summarize an empty list from a FAILED roster
 * read - a read failure must resolve to {@link failedExclusiveEgressStatus}
 * (which caps green), NEVER to `summarizeExclusiveEgressStatus([])`. Likewise
 * a provider that cannot determine state must throw or return
 * `failedExclusiveEgressStatus`, never a bare empty summary. This function
 * cannot distinguish "genuinely none" from "lost the roster"; the producer
 * owns that distinction and the fail-closed choice.
 */
export function summarizeExclusiveEgressStatus(
  agents: ReadonlyArray<ExclusiveEgressPosture>,
): ExclusiveEgressStatus {
  const declared = agents.filter((a) => a.fine_grained_declared);
  const fineGrainedDeclared = declared.length > 0;
  const live =
    declared.length > 0
      ? declared.every((a) => a.mode === "exclusive")
      : true;
  let worst: ExclusiveEgressMode | null = null;
  for (const agent of declared) {
    if (worst === null || MODE_SEVERITY[agent.mode] < MODE_SEVERITY[worst]) {
      worst = agent.mode;
    }
  }
  const reasons: string[] = [];
  for (const agent of declared) {
    if (agent.mode === "exclusive") continue;
    reasons.push(
      `uid ${agent.agent_uid}: ${agent.mode}${
        agent.reasons.length > 0 ? ` (${agent.reasons.join("; ")})` : ""
      }`,
    );
  }
  return {
    fine_grained_declared: fineGrainedDeclared,
    exclusive_egress_live: fineGrainedDeclared ? live : true,
    mode: worst,
    agents: [...agents],
    reasons,
  };
}

/**
 * THE ONE CAPPING RULE (design §6): aggregate wall-green must be capped to a
 * distinct non-green when a fine-grained-provisioned agent's exclusive-egress
 * stack is not live. Consumed by `buildCastleWallPosture` (the single source
 * of `arm_state`) and `buildFeatureHealthPanel` (the `castle_wall_egress`
 * row) so no surface can compute a different answer. Null/undefined status =
 * no producer wired = no fine-grained agent exists = no cap.
 */
export function exclusiveEgressCapsAggregateGreen(
  status: ExclusiveEgressStatus | null | undefined,
): boolean {
  if (status === null || status === undefined) return false;
  return status.fine_grained_declared && !status.exclusive_egress_live;
}

/**
 * The FAIL-CLOSED stand-in a surface must use when its wired exclusive-egress
 * posture provider THROWS: a provider only exists on a fleet that provisioned
 * fine-grained mode, so a failed read means "cannot prove exclusive-egress
 * live" - which must cap green, never silently read as "no fine-grained
 * agents" (that would be the exact silent-degrade HIGH-3 forbids).
 */
export function failedExclusiveEgressStatus(reason: string): ExclusiveEgressStatus {
  return {
    fine_grained_declared: true,
    exclusive_egress_live: false,
    mode: null,
    agents: [],
    reasons: [`exclusive-egress posture read failed: ${reason}`],
  };
}
