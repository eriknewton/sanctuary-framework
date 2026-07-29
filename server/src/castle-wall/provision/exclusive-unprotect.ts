/**
 * Unified Protect Slice 5 S5-7: per-agent UNPROTECT via the locked pf-anchor
 * registry -- the reversibility half of the exclusive-egress stack (design
 * rev3 `Unified_Protect_Slice5_InstallFusion_Design_2026-07-14.md`, S5-7 row:
 * registry remove, union re-load, per-remaining-uid liveness, gate daemon +
 * credential + policy teardown; flush only when the last agent leaves;
 * idempotent re-run).
 *
 * WHAT THIS RETIRES: S5-1's registry shipped `remove()` (union re-render +
 * per-remaining-uid liveness + last-leaves flush) but nothing sequenced the
 * FULL per-agent teardown around it -- the gate daemon, the generation-bound
 * credential, the oracle freshness token, the gate policy surfaces, and the
 * release-barrier hold state all outlive a bare registry remove. This module
 * is that sequencing layer, pure over injected ops (production wiring:
 * `egress-gate/arming-wiring.ts` `createUnprotectExclusiveEgressOps`).
 *
 * CONCURRENCY + INVARIANT (S5-7 fix-round-2, replacing the fix-round's
 * sibling-retention model). The whole sequence runs UNDER THE PROVISION LOCK
 * (`withUnprotectLock` -> `withProvisionLock(PROVISION_LOCK_PATH, ...)`, the
 * SAME lock the arm/repair paths take), so arm, repair, and unprotect are
 * mutually exclusive and two unprotects serialize -- closing the HIGH-1 TOCTOU
 * where a lockless registry snapshot let a concurrent `protect --exclusive-egress`
 * commit a sibling between the read and the teardown. UNDER THE LOCK, step 0
 * ASSERTS the one-exclusive-agent-per-fortress/harness invariant: the exclusive
 * marker names ONE uid and a second exclusive install overwrites the first's
 * marker, so the ONLY reachable v1 state is exactly one exclusive agent per
 * fortress/harness. If any OTHER committed non-tombstone registry entry shares
 * the leaving uid's fortress or harness, the state is a future multi-agent
 * config this per-agent teardown cannot safely handle (the routing marker, gate
 * policy file, and harness-keyed provisioned rules are ALL single-uid/harness-
 * keyed -- half-tearing one a sibling still needs is the HIGH-2/HIGH-3 defect):
 * it REFUSES, fail-closed and loud, leaving every surface + the registry entry
 * intact. When the invariant holds (the sole-user case) the teardown is FULL --
 * the leaving uid is the only user, so tearing down every shared surface is
 * correct.
 *
 * ORDERING (mirrors `restoreCoarseCompositionProduction`'s rationale, and the
 * S5-1 registry-last rule):
 *   1. PARK the harness (verified persistent park: not running + launchd
 *      override-db read-back + hold file absent + parked plist -- or an ABSENT
 *      plist under the argv-unavailable fallback, which the verify accepts).
 *      The leaving agent's process must be DOWN and unbootable before any of
 *      its confinement is dismantled -- removing the registry entry drops the
 *      uid's four block-drops, so a still-running agent would be UNCONFINED.
 *   2. RECOVER any in-flight generation (the S5-2 crash table: a dead pre-pf
 *      staging record is discarded; a staged-but-uncommitted generation is
 *      block-only tombstoned with its generation id carried into the entry,
 *      so step 7's remove folds it into the persisted floor).
 *   3. GATE DAEMON DOWN (bootout; "no such process" is success, any other
 *      failure THROWS -- never tear down credential/policy/registry surfaces
 *      under a possibly-live gate, the exact reviewed S5-6 M5 defect).
 *   4. CREDENTIAL teardown: oracle freshness token invalidated + the
 *      generation-bound bearer credential revoked (file + gate accept-state,
 *      design M5: "unprotect removes the file and the gate-side accept-state").
 *   5. MANIFEST scrub: every `provisioned-<harness>-*` rule removed from the
 *      signing source + verified none survive (the agent is LEAVING; its
 *      grants must not survive as orphans -- gate-scoped OR agent-scoped),
 *      then the signing daemon reloaded (a reload failure is reported, not
 *      thrown, because the rules are already gone from the signing source).
 *      Runs BEFORE the routing-marker removal (fix-round LOW-2): scrubbing
 *      first means a crash-then-external-reload window composes
 *      marker-present-but-no-rules (agent BLOCKED, fail-closed), never
 *      marker-gone-but-rules-present (agent-scoped direct grants, fail-open).
 *   6. POLICY teardown: gate-readable runtime config copies, gate daemon plist,
 *      per-uid gate runtime dir, AND the exclusive routing marker + gate policy
 *      file -- the leaving uid is the sole user (asserted in step 0), so every
 *      surface is torn down.
 *   7. REGISTRY REMOVE, LAST: the union re-renders WITHOUT the leaving uid and
 *      the anchor is FLUSHED (the registry's one sanctioned `-F all`); the
 *      leaving uid's own generation_id folds into the persisted generation
 *      floor so a later re-protect cannot reuse it. (Any tombstone-only residue
 *      of another uid re-verifies exact-live by the registry's own transaction
 *      machinery -- never a partial union.)
 *
 * FAIL-CLOSED DIRECTION: a step-0 invariant violation (or an unreadable
 * registry) REFUSES with NOTHING torn down; every later-stage failure returns
 * an honest staged outcome and LEAVES THE PROTECTION IN PLACE -- a failure
 * before step 7 leaves the leaving uid's block-drops live (over-restrictive:
 * the parked agent is down AND still confined), and a step-7 failure rolls
 * back inside the registry's own journaled transaction (dirty = loud repair
 * signal). IDEMPOTENT: every step tolerates already-torn-down, so a re-run
 * after any failure converges to the same terminal state (an absent uid's
 * remove() is a reconciling no-op).
 *
 * HONEST BOUNDS: this is the per-agent EXCLUSIVE-EGRESS teardown for the
 * SOLE-USER (single-exclusive-agent) case only. The shared-fortress
 * multi-agent teardown is explicitly OUT OF SCOPE and REFUSED fail-closed
 * (step 0), never silently mishandled. It does not delete the agent or gate
 * service accounts (Erik-present, out of scope by standing decision), does not
 * restore re-homed files or disarm the coarse wall (`unprovision.ts` owns that
 * flow), and advances no capability claim -- the multi-uid unprotect drill
 * (S5-DRILL leg 6: two confined uids, unprotect one, sibling confinement
 * verified INTACT under a concurrent probe loop) is owed before any external
 * claim.
 */

import { ProvisionLockHeldError } from "./lockfile.js";
import { EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE } from "../../egress-gate/operator-advice.js";

/** Distinct local audit operation strings (never a widened shared enum). */
export const EGRESS_GATE_UNPROTECT_AUDIT_OP = "egress_gate_unprotected";
export const EGRESS_GATE_UNPROTECT_FAILED_AUDIT_OP = "egress_gate_unprotect_failed";
export const EGRESS_GATE_UNPROTECT_REFUSED_AUDIT_OP = "egress_gate_unprotect_refused";

/** The teardown stage a failure is attributed to (in execution order). */
export type EgressGateUnprotectStage =
  | "park"
  | "recover"
  | "gate-daemon"
  | "credential"
  | "manifest-scrub"
  | "policy"
  | "registry";

/** Context for one unprotect run. */
export interface EgressGateUnprotectContext {
  agentUid: number;
}

/**
 * Injected side effects for the unprotect sequence. Production
 * (`egress-gate/arming-wiring.ts`) maps these onto the REAL primitives; every
 * op MUST be idempotent (tolerate already-torn-down) and throw on genuine
 * failure.
 */
export interface EgressGateUnprotectOps {
  /**
   * Hold the exclusive provision lock (the SAME lock the arm/repair paths take,
   * `PROVISION_LOCK_PATH`) around the WHOLE unprotect sequence, so arm, repair,
   * and unprotect are mutually exclusive and two unprotects serialize (S5-7
   * fix-round-2 HIGH-1). Production maps this to `withProvisionLock`. Throws
   * `ProvisionLockHeldError` when another provisioning run holds the lock; the
   * sequence converts that to a fail-closed `unprotect-refused` outcome (never
   * proceeds under contention).
   */
  withUnprotectLock<T>(fn: () => Promise<T>): Promise<T>;
  /**
   * UNDER THE LOCK, assert the one-exclusive-agent-per-fortress/harness
   * invariant (production: read the committed non-tombstone registry set): `ok`
   * only when the leaving uid is the SOLE exclusive agent; otherwise the
   * `conflictingUids` are the other committed uids sharing its fortress or
   * harness, and the teardown REFUSES fail-closed rather than half-tearing a
   * single-uid shared surface a sibling still needs. Throws on an unreadable
   * registry (the sequence converts that to a fail-closed refusal).
   */
  assertSoleUserInvariant(): Promise<{ ok: true } | { ok: false; conflictingUids: number[] }>;
  /**
   * Verified persistent park (production: `parkHarnessPersistently`): bootout
   * + persistent disable + hold-file removal + parked-plist restore, then the
   * full parked posture VERIFIED. Throws unless the agent is provably down
   * and unbootable -- the sequence never dismantles a running agent's
   * confinement.
   */
  parkHarness(): Promise<void>;
  /**
   * The honest-park probe for failure outcomes (production:
   * `verifyHarnessParkedPersistent`): never throws by contract of the caller
   * (a throwing probe reads as not-verified).
   */
  verifyParkedPersistent(): Promise<{ ok: true } | { ok: false; problems: string[] }>;
  /**
   * Resolve any in-flight (uncommitted) generation per the S5-2 crash table
   * (production: `GenerationCoordinator.recover`). A tombstoned dead
   * generation keeps its id in the registry entry, so the final remove folds
   * it into the persisted generation floor. Throws on failure.
   */
  recoverGeneration(): Promise<void>;
  /**
   * Stop the leaving uid's gate daemon (production: `launchctl bootout`).
   * Not-running/not-found is SUCCESS; any other failure THROWS loudly --
   * never `.catch(() => undefined)`.
   */
  bootoutGateDaemon(): Promise<void>;
  /** Invalidate the uid's oracle freshness token (production: `GateLivenessOracle.invalidate`). */
  invalidateOracleToken(): Promise<void>;
  /**
   * Revoke the uid's generation-bound bearer credential: token file AND gate
   * accept-state (production: `GateCredentialAuthority.revoke`).
   */
  revokeCredential(): Promise<void>;
  /**
   * Remove the uid's gate policy surfaces. Because step 0 asserted the leaving
   * uid is the SOLE exclusive agent, every surface is torn down: the per-uid
   * surfaces (gate-readable runtime config copies, gate daemon plist, per-uid
   * runtime dir) AND the fortress exclusive routing marker + gate policy file.
   * Each removal idempotent (`rm -f`).
   */
  removeGateSurfaces(): Promise<void>;
  /**
   * Remove every provisioned egress rule for the leaving harness from the
   * signing source and VERIFY none survive, then reload the signing daemon
   * (production: `scrubProvisionedEgressRules`). Throws when a rule survives
   * the scrub; a reload failure is reported via `reloadOk`, not thrown (the
   * rules are already gone from the signing source).
   */
  scrubProvisionedRules(): Promise<{ removedRuleIds: string[]; reloadOk: boolean }>;
  /**
   * The S5-1 registry remove for the leaving uid: union re-render WITHOUT the
   * uid, per-remaining-uid exact-union liveness, flush ONLY when the set
   * becomes empty, generation floor folded. Returns the remaining confined
   * uids, whether the anchor was flushed (last agent left), and whether the
   * registry is dirty (repair owed -- loud, never silent).
   */
  removeRegistryEntry(): Promise<{ remainingUids: number[]; flushed: boolean; dirty: boolean }>;
  /** Best-effort audit (distinct local ops). MUST never throw. */
  audit(operation: string, details: Record<string, unknown>): Promise<void>;
  /** Operator-facing progress line. */
  print(line: string): void;
}

/** Terminal outcome of one unprotect run. */
export type EgressGateUnprotectOutcome =
  /**
   * The full per-agent teardown completed: agent parked, gate surfaces gone,
   * registry entry removed with every remaining uid's confinement re-verified
   * live. `flushed` is true ONLY when this was the last confined uid (the
   * registry's one sanctioned flush). `registryDirty` true means the remove
   * committed but the registry still carries a repair-owed marker (e.g. a
   * preserved malformed generation-floor raw) -- posture stays non-green and
   * the caller must say so loudly.
   */
  | { kind: "unprotected"; remainingUids: number[]; flushed: boolean; registryDirty: boolean }
  /**
   * The teardown failed at `stage`. Remaining protection is INTACT (a
   * pre-registry failure leaves the leaving uid's block-drops live; a
   * registry-stage failure rolled back inside the registry's journaled
   * transaction). The parked claim is honest (S5-6 fix-round-2 HIGH-2):
   * `parkedStateVerified` is true only when a probe confirmed the FULL
   * persistent parked posture; `parkedStateProblems` enumerates what failed.
   */
  | {
      kind: "unprotect-failed";
      stage: EgressGateUnprotectStage;
      reason: string;
      parkedStateVerified: boolean;
      parkedStateProblems: string[];
    }
  /**
   * The teardown was REFUSED before any surface was touched (fail-closed):
   * either the sole-exclusive-agent invariant does not hold (`conflictingUids`
   * names the other committed uids sharing the fortress/harness -- per-agent
   * unprotect of a shared-fortress multi-agent config is out of scope until the
   * multi-agent teardown lands), the committed registry could not be read to
   * assert the invariant, or another provisioning run holds the provision lock.
   * EVERY surface + the registry entry are left INTACT; the caller maps this to
   * a non-zero exit and a loud message.
   */
  | { kind: "unprotect-refused"; reason: string; conflictingUids: number[] };

/**
 * Run the per-agent exclusive-egress unprotect sequence UNDER THE PROVISION
 * LOCK (S5-7 fix-round-2 HIGH-1). See the module doc for ordering + fail-closed
 * rationale. Never throws: a held provision lock, an invariant violation, an
 * unreadable registry, or any staged failure is an honest outcome the
 * production CLI maps to a non-zero exit.
 */
export async function runEgressGateUnprotect(
  ctx: EgressGateUnprotectContext,
  ops: EgressGateUnprotectOps,
): Promise<EgressGateUnprotectOutcome> {
  const refuse = async (
    reason: string,
    conflictingUids: number[],
  ): Promise<EgressGateUnprotectOutcome> => {
    await ops.audit(EGRESS_GATE_UNPROTECT_REFUSED_AUDIT_OP, {
      agent_uid: ctx.agentUid,
      reason,
      conflicting_uids: conflictingUids,
    });
    return { kind: "unprotect-refused", reason, conflictingUids };
  };
  try {
    return await ops.withUnprotectLock(() => runUnprotectSequenceLocked(ctx, ops, refuse));
  } catch (err) {
    // The provision lock is held by another arm/repair/unprotect run: refuse
    // fail-closed (nothing was touched -- acquisition precedes the sequence).
    if (err instanceof ProvisionLockHeldError) {
      return refuse(
        "another sanctuary provisioning run holds the exclusive provision lock; refusing to unprotect " +
          `concurrently (nothing torn down): ${err.message}`,
        [],
      );
    }
    throw err;
  }
}

/**
 * The locked unprotect body: step 0 invariant assertion + the ordered teardown.
 * Runs inside {@link runEgressGateUnprotect}'s `withUnprotectLock`, so the
 * committed registry it reads cannot change under it.
 */
async function runUnprotectSequenceLocked(
  ctx: EgressGateUnprotectContext,
  ops: EgressGateUnprotectOps,
  refuse: (reason: string, conflictingUids: number[]) => Promise<EgressGateUnprotectOutcome>,
): Promise<EgressGateUnprotectOutcome> {
  // 0. INVARIANT (fail-closed). The exclusive marker/gate-policy/provisioned
  // rules are single-uid/harness-keyed; a per-agent teardown is only safe when
  // the leaving uid is the sole exclusive agent. A shared-fortress/harness
  // sibling (or an unreadable registry) REFUSES -- nothing is torn down.
  let invariant: { ok: true } | { ok: false; conflictingUids: number[] };
  try {
    invariant = await ops.assertSoleUserInvariant();
  } catch (err) {
    return refuse(
      "could not read the committed registry to assert the sole-exclusive-agent invariant " +
        `(fail-closed; nothing torn down): ${(err as Error).message}`,
      [],
    );
  }
  if (!invariant.ok) {
    return refuse(
      "per-agent unprotect of a shared-fortress/harness agent is not supported until the multi-agent " +
        "teardown lands; refusing to tear down single-uid shared surfaces (routing marker, gate policy, " +
        `harness-keyed rules) a sibling still needs (conflicting confined uid(s): ${invariant.conflictingUids.join(", ")})`,
      invariant.conflictingUids,
    );
  }

  const fail = async (
    stage: EgressGateUnprotectStage,
    reason: string,
  ): Promise<EgressGateUnprotectOutcome> => {
    let parked: { ok: true } | { ok: false; problems: string[] };
    try {
      parked = await ops.verifyParkedPersistent();
    } catch (err) {
      parked = { ok: false, problems: [`parked-state verify probe threw: ${(err as Error).message}`] };
    }
    await ops.audit(EGRESS_GATE_UNPROTECT_FAILED_AUDIT_OP, {
      agent_uid: ctx.agentUid,
      stage,
      reason,
      parked_state_verified: parked.ok,
    });
    return {
      kind: "unprotect-failed",
      stage,
      reason,
      parkedStateVerified: parked.ok,
      parkedStateProblems: parked.ok ? [] : parked.problems,
    };
  };

  // 1. Park (verified). The agent must be down + unbootable before its
  // confinement is dismantled.
  try {
    await ops.parkHarness();
  } catch (err) {
    return fail("park", `could not park the harness before unprotect: ${(err as Error).message}`);
  }

  // 2. Recover any in-flight generation (staging record resolved per the
  // crash table; a dead generation's id is carried so step 7 folds it).
  try {
    await ops.recoverGeneration();
  } catch (err) {
    return fail("recover", `could not recover the in-flight generation state: ${(err as Error).message}`);
  }

  // 3. Gate daemon down FIRST among the gate surfaces (S5-6 M5 rationale).
  try {
    await ops.bootoutGateDaemon();
  } catch (err) {
    return fail(
      "gate-daemon",
      `could not stop the egress-gate daemon (refusing to tear down credential/policy/registry ` +
        `surfaces under a possibly-live gate): ${(err as Error).message}`,
    );
  }

  // 4. Credential teardown: freshness token + bearer credential (file AND
  // gate accept-state, design M5).
  try {
    await ops.invalidateOracleToken();
    await ops.revokeCredential();
  } catch (err) {
    return fail("credential", `could not tear down the gate credential surfaces: ${(err as Error).message}`);
  }

  // 5. Manifest scrub (no orphan grants for a leaving agent) + reload. This
  // runs BEFORE the routing-marker removal (fix-round LOW-2): a crash between
  // marker removal and the scrub, followed by an external policy-daemon reload,
  // would otherwise compose the still-present provisioned rules AGENT-SCOPED
  // (direct grants, no gate = fail-open). Scrubbing first means a crash in this
  // window leaves marker-present-but-no-rules (the agent is BLOCKED, fail-closed).
  let scrub: { removedRuleIds: string[]; reloadOk: boolean };
  try {
    scrub = await ops.scrubProvisionedRules();
  } catch (err) {
    return fail("manifest-scrub", `provisioned-rule scrub failed: ${(err as Error).message}`);
  }
  if (!scrub.reloadOk) {
    // The rules are gone from the signing source (the scrub verified that);
    // a still-running daemon just has not re-composed yet. Loud, not fatal:
    // the next daemon load cannot resurrect scrubbed rules.
    ops.print(
      "[castle-wall] unprotect: the provisioned rules are scrubbed from the signing source but the " +
        "policy daemon reload could not be confirmed; the running daemon may serve the old compose " +
        "until its next reload.",
    );
  }

  // 6. Policy surfaces off. Step 0 asserted the leaving uid is the sole
  // exclusive agent, so every surface goes: per-uid gate surfaces AND the
  // fortress routing marker + gate policy file.
  try {
    await ops.removeGateSurfaces();
  } catch (err) {
    return fail("policy", `could not remove the gate policy surfaces: ${(err as Error).message}`);
  }

  // 7. Registry remove, LAST. Union re-render preserves every remaining uid;
  // flush only when the set becomes empty; generation floor folded.
  let removal: { remainingUids: number[]; flushed: boolean; dirty: boolean };
  try {
    removal = await ops.removeRegistryEntry();
  } catch (err) {
    return fail(
      "registry",
      `registry remove failed (the registry's journaled transaction preserves the previous union; ` +
        `remaining uids stay confined): ${(err as Error).message}`,
    );
  }

  await ops.audit(EGRESS_GATE_UNPROTECT_AUDIT_OP, {
    agent_uid: ctx.agentUid,
    remaining_uids: removal.remainingUids,
    anchor_flushed: removal.flushed,
    registry_dirty: removal.dirty,
    scrubbed_rule_ids: scrub.removedRuleIds,
    reload_confirmed: scrub.reloadOk,
  });
  ops.print(
    removal.flushed
      ? `[castle-wall] unprotect: uid ${ctx.agentUid} removed; no confined agents remain -- the pf ` +
          "anchor was flushed (the registry's one sanctioned flush)."
      : `[castle-wall] unprotect: uid ${ctx.agentUid} removed; ${removal.remainingUids.length} confined ` +
          `agent(s) remain and their confinement re-verified live (uids ${removal.remainingUids.join(", ")}).`,
  );
  if (removal.dirty) {
    ops.print(
      "[castle-wall] unprotect: the registry still carries a repair-owed marker (posture stays " +
        `non-green). Run: ${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE}`,
    );
  }
  return {
    kind: "unprotected",
    remainingUids: removal.remainingUids,
    flushed: removal.flushed,
    registryDirty: removal.dirty,
  };
}
