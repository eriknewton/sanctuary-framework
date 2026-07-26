/**
 * NEFilter-manifest / pf-anchor policy-parity guard (Unified Protect
 * Slice 8).
 *
 * Two enforcement surfaces now express ONE intent: the signed NEFilter
 * manifest carries the derived `.agent`-scoped gate allow rule, and the pf
 * anchor confines agent-uid loopback to the same gate port. Two policies
 * generated for one intent is a classic drift-and-bypass vector (a rule in
 * one surface but not the other is a hole), so both artifacts are generated
 * from the single `ExclusiveEgressGatePolicy` source and this guard asserts
 * they agree. It mirrors the existing Swift/TS evaluator parity invariant.
 *
 * The check is CI-runnable (pure string/structure comparison, no pf, no
 * root): `test/egress-gate/parity.test.ts` runs it over a fixture corpus
 * including deliberately-divergent policies that MUST fail.
 */

import type { AllowlistRule } from "../castle-wall/allowlist/schema.js";
import {
  DERIVED_GATE_RULE_ID,
  GATE_LOOPBACK_CIDR,
  deriveGateAllowRule,
  validateExclusiveEgressGatePolicy,
  type ExclusiveEgressGatePolicy,
} from "../castle-wall/allowlist/gate-derivation.js";
import { renderPfAnchorRules } from "./pf-anchor.js";

/** Inputs to {@link checkGatePolicyParity}. */
export interface GatePolicyParityInput {
  /** The single-source policy both artifacts claim to be generated from. */
  policy: ExclusiveEgressGatePolicy;
  /** The composed manifest ruleset (as signed / about to be signed). */
  manifestRules: readonly AllowlistRule[];
  /** The pf anchor rule text (as loaded / about to be loaded). */
  pfAnchorText: string;
  /**
   * Exclusive routing (Slice 5 S5-4): the manifest was composed with the
   * gate-channel rule scoped to the agent principal
   * (`scope.uids = [agent_uid]`). The parity expectation derives the SAME
   * form; a manifest whose gate rule carries the wrong scope for the
   * composition mode is drift. Default false (legacy empty scope).
   */
  gateRuleScopedToAgentUid?: boolean;
}

/**
 * Assert that the manifest gate rule and the pf anchor both match what the
 * single-source policy generates. Returns issues (empty means parity
 * holds). Checks, in order:
 *
 *   1. the policy itself is well-formed;
 *   2. EXACTLY ONE derived gate rule is present in the manifest ruleset and
 *      it is byte-identical (canonical JSON) to `deriveGateAllowRule(policy)`
 *      modulo the `created_at` timestamp;
 *   3. the pf anchor text is exactly `renderPfAnchorRules(policy)`;
 *   4. cross-artifact: the gate port and destination the manifest rule
 *      allows are the same port/destination the pf pass rule allows (a
 *      redundant re-derivation guarding against a bug in 2/3 themselves).
 */
export function checkGatePolicyParity(input: GatePolicyParityInput): string[] {
  const issues: string[] = [];

  const policy = validateExclusiveEgressGatePolicy(input.policy);
  if (policy === null) {
    return ["gate policy is structurally invalid; nothing can be parity-checked from it"];
  }

  // 2. Manifest side.
  const gateRules = input.manifestRules.filter((r) => r.id === DERIVED_GATE_RULE_ID);
  if (gateRules.length !== 1) {
    issues.push(
      `manifest carries ${gateRules.length} "${DERIVED_GATE_RULE_ID}" rules; exactly one is required for parity`,
    );
  } else {
    const found = gateRules[0]!;
    const expected = deriveGateAllowRule(policy, found.created_at, {
      scope_to_agent_uid: input.gateRuleScopedToAgentUid === true,
    });
    if (JSON.stringify(normalizeRule(found)) !== JSON.stringify(normalizeRule(expected))) {
      issues.push(
        `manifest gate rule diverges from the single-source derivation for ` +
          `uid ${policy.agent_uid} / port ${policy.gate_port}`,
      );
    }
  }

  // 3. pf side: byte-for-byte against the single-source render.
  const expectedAnchor = renderPfAnchorRules(policy);
  if (input.pfAnchorText !== expectedAnchor) {
    issues.push("pf anchor text diverges from the single-source render for this policy");
  }

  // 4. Cross-artifact redundancy: independently parse the pf pass rule and
  // compare its port against the manifest rule's port list.
  const passMatch = /^pass quick on lo0 inet proto tcp from any to 127\.0\.0\.1 port = (\d+) user = (\d+) /m.exec(
    input.pfAnchorText,
  );
  if (!passMatch) {
    issues.push("pf anchor text has no parseable agent-to-gate pass rule");
  } else {
    const pfPort = Number(passMatch[1]);
    const pfUid = Number(passMatch[2]);
    if (pfPort !== policy.gate_port) {
      issues.push(`pf pass rule allows port ${pfPort} but the policy gate port is ${policy.gate_port}`);
    }
    if (pfUid !== policy.agent_uid) {
      issues.push(`pf pass rule scopes uid ${pfUid} but the policy agent uid is ${policy.agent_uid}`);
    }
    if (gateRules.length === 1) {
      const ports = gateRules[0]!.match.port;
      const portList = Array.isArray(ports) ? ports : ports !== undefined ? [ports] : [];
      if (portList.length !== 1 || portList[0] !== pfPort) {
        issues.push(
          `manifest gate rule allows port(s) [${portList.join(", ")}] but the pf pass rule allows ${pfPort}`,
        );
      }
      const cidr = gateRules[0]!.match.cidr;
      const cidrList = Array.isArray(cidr) ? cidr : cidr !== undefined ? [cidr] : [];
      if (cidrList.length !== 1 || cidrList[0] !== GATE_LOOPBACK_CIDR) {
        issues.push(
          `manifest gate rule destination [${cidrList.join(", ")}] is not the pinned ${GATE_LOOPBACK_CIDR}`,
        );
      }
    }
  }

  return issues;
}

/** Thrown when {@link checkGatePolicyParity} finds drift. */
export class GatePolicyParityError extends Error {
  readonly issues: readonly string[];
  constructor(issues: readonly string[]) {
    super(
      "Exclusive-egress policy parity violated: the NEFilter manifest rule and the pf anchor " +
        `disagree.\n  - ${issues.join("\n  - ")}\nBoth artifacts must be generated from the ` +
        "same gate policy; drift between them is a bypass hole.",
    );
    this.name = "GatePolicyParityError";
    this.issues = issues;
  }
}

/** Throwing form of {@link checkGatePolicyParity} for pipeline call sites. */
export function assertGatePolicyParity(input: GatePolicyParityInput): void {
  const issues = checkGatePolicyParity(input);
  if (issues.length > 0) {
    throw new GatePolicyParityError(issues);
  }
}

/** Stable-key normalization so property order never masks / fakes drift. */
function normalizeRule(rule: AllowlistRule): unknown {
  return deepSortKeys(rule);
}

function deepSortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(deepSortKeys);
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      out[key] = deepSortKeys(record[key]);
    }
    return out;
  }
  return value;
}
