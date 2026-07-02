/**
 * Exclusive-egress gate rule derivation (Unified Protect Slice 1).
 *
 * The exclusive-egress posture confines the agent's only permitted network
 * destination to the local policy gate on loopback TCP. This module is the
 * SINGLE SOURCE for the gate policy shape: the same validated
 * `ExclusiveEgressGatePolicy` object derives BOTH the `.agent`-scoped
 * NEFilter manifest allow rule (here) and the per-uid pf anchor
 * (`egress-gate/pf-anchor.ts`). The parity guard in `egress-gate/parity.ts`
 * asserts the two generated artifacts agree, mirroring the Swift/TS
 * evaluator parity invariant.
 *
 * Security invariants (tested):
 *   - A malformed policy derives NO rule (fail closed: the agent simply
 *     cannot reach the gate, which is the deny side; a half-built policy is
 *     never signed into the manifest).
 *   - The derived rule allows exactly `127.0.0.1/32` on exactly the gate
 *     port over TCP, nothing wider. It never widens off-box egress: the
 *     destination is loopback-only by construction.
 *   - The derived rule carries `derived: true` so policy introspection
 *     surfaces it (never a silently-invisible grant, same as #380).
 *
 * ENFORCEMENT HONESTY: the NEFilter content filter is proven BLIND to
 * loopback traffic (2026-06-30 drill), so this manifest rule is
 * belt-and-suspenders for the delivery case, and the actual loopback
 * confinement is the pf anchor (proven on Tahoe 2026-07-02, N=3;
 * drill-acceptance for the composed build is PENDING). Routing is
 * kernel-enforced; destination policy at the gate is userspace-enforced;
 * loopback confinement is pf-enforced.
 */

import type { AllowlistRule } from "./schema.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../constants.js";

/** Stable id for the derived exclusive-egress gate allow rule. */
export const DERIVED_GATE_RULE_ID = "derived_exclusive_egress_gate";

/** The loopback destination the gate rule allows. Never anything wider. */
export const GATE_LOOPBACK_CIDR = "127.0.0.1/32";

/** Fortress-relative config filename the daemon loads the policy from. */
export const EXCLUSIVE_EGRESS_GATE_FILENAME = "exclusive-egress-gate.json";

/**
 * The exclusive-egress gate policy: the one source of truth from which the
 * NEFilter manifest allow rule and the pf loopback anchor are both derived.
 * Field names are snake_case to match the on-disk config convention
 * (`policy/egress/exclusive-egress-gate.json`, like `agent-origin.json`).
 */
export interface ExclusiveEgressGatePolicy {
  /** The dedicated agent service-account uid the pf anchor confines. */
  agent_uid: number;
  /** The loopback TCP port the policy gate listens on. */
  gate_port: number;
}

function isNonNegativeInt(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= 0;
}

function isValidPort(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 65535;
}

/**
 * Validate and normalize a candidate gate policy (untrusted JSON from config
 * or fixture). Returns a NEW object with only the two policy fields, or
 * `null` when the candidate is unusable.
 *
 * FAIL-CLOSED RATIONALE: `null` means "derive no allow rule", so the agent
 * cannot reach any gate port. That is the deny side. The failure mode this
 * guards against is a malformed policy (e.g. a string uid, port 0, a
 * negative uid) being signed into the manifest and later disagreeing with
 * the pf anchor generated from the same bytes.
 *
 * `agent_uid` 0 (root) is REJECTED: confining root with a per-uid rule is
 * meaningless (root can alter pf), and a gate policy claiming the agent is
 * root indicates a provisioning bug.
 */
export function validateExclusiveEgressGatePolicy(
  candidate: unknown,
): ExclusiveEgressGatePolicy | null {
  if (candidate === null || typeof candidate !== "object") {
    return null;
  }
  const c = candidate as Record<string, unknown>;
  if (!isNonNegativeInt(c.agent_uid) || c.agent_uid === 0) {
    return null;
  }
  if (!isValidPort(c.gate_port)) {
    return null;
  }
  return { agent_uid: c.agent_uid, gate_port: c.gate_port };
}

/**
 * Derive the `.agent`-scoped manifest allow rule for the gate channel:
 * destination `127.0.0.1/32`, the gate port, TCP, disposition allow, empty
 * scope (all wrapped agents; the evaluator only consults rules for
 * agent-classified flows, so this rule never widens operator posture).
 *
 * Callers MUST pass a policy that already survived
 * {@link validateExclusiveEgressGatePolicy}; this function re-validates and
 * throws on a malformed policy rather than emitting a malformed rule.
 */
export function deriveGateAllowRule(
  policy: ExclusiveEgressGatePolicy,
  createdAt: string,
): AllowlistRule {
  if (validateExclusiveEgressGatePolicy(policy) === null) {
    throw new Error(
      "deriveGateAllowRule: refusing to derive a manifest rule from a malformed exclusive-egress gate policy",
    );
  }
  return {
    id: DERIVED_GATE_RULE_ID,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: createdAt,
    description:
      "Exclusive-egress gate channel: agent loopback TCP to the local policy gate " +
      `(127.0.0.1:${policy.gate_port}). Auto-derived from the gate policy; ` +
      "the per-uid pf anchor is generated from the same source.",
    match: {
      cidr: GATE_LOOPBACK_CIDR,
      port: [policy.gate_port],
      protocol: "tcp",
    },
    scope: {},
    disposition: "allow",
    derived: true,
  };
}
