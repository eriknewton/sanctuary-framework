/**
 * Sanctuary Attestation UX -- False-Green Guard (B4 hardening, 2026-07-04)
 *
 * Adversarial regression suite for the badge-state derivation. The badge is
 * the operator's single at-a-glance truth signal; a badge that renders green
 * ("Walls sound") for an event that is actually degraded, unverified,
 * tampered, or absent is a false-green defect: it tells the operator the
 * walls are sound when they are not.
 *
 * Root cause closed by this guard: the pre-fix derivation enumerated
 * specific bad values (red / yellow) and fell through to green for anything
 * else. That is fail-open. Any input the code did not explicitly recognize
 * as bad, including a "red" or "offline" on the audit chain / policy sync /
 * guardian subsystem, an "offline" annex, and an unrecognized or corrupt
 * value, was silently treated as nominal and rendered green.
 *
 * Every case below was reproducible as a FALSE-GREEN on the pre-fix code:
 *   deriveGlobalBadge / deriveAgentBadge returned "green"; deriveActionBadge
 *   returned an unrecognized value verbatim. After the fail-closed fix each
 *   case degrades to a truthful state (never "green", never a raw unknown).
 *
 * Honesty scope: the badge reflects LOCAL evidence classification only. This
 * guard proves the derivation never renders green for a non-nominal or
 * unrecognized input; it makes no hardware / TEE guarantee.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  deriveGlobalBadge,
  deriveAgentBadge,
  deriveActionBadge,
  applyAttestationEvent,
  clearAllBadgeStores,
} from "../../src/attestation/badge-state.js";
import {
  BADGE_STATES,
  SIGNATURE_SCHEME_V1,
} from "../../src/attestation/constants.js";
import type {
  ActionLayerContext,
  AgentLayerContext,
  AttestationEvent,
  GlobalLayerContext,
} from "../../src/attestation/types.js";

// A value outside the closed BADGE_STATES enum: a buggy / truncated /
// tampered producer signal. The types say BadgeStateColor, but the context
// objects are assembled at runtime from live signals, so an off-enum value
// can arrive. It must never be treated as nominal.
const CORRUPT = "purple" as unknown as GlobalLayerContext["audit_chain_state"];

function allGreenGlobal(
  overrides?: Partial<GlobalLayerContext>
): GlobalLayerContext {
  return {
    fortress_id: "f-1",
    node_states: { "node-1": "green", "node-2": "green" },
    audit_chain_state: "green",
    policy_sync_state: "green",
    guardian_state: "green",
    agent_badge_states: { "agent-1": "green" },
    ...overrides,
  };
}

function allGreenAgent(
  overrides?: Partial<AgentLayerContext>
): AgentLayerContext {
  return {
    agent_id: "a-1",
    fortress_id: "f-1",
    bound_node_id: "node-1",
    node_attestation_state: "green",
    identity_valid: true,
    policy_pinned: true,
    policy_version: 1,
    annex_states: { "annex-1": "green" },
    egress_enforcing: true,
    ...overrides,
  };
}

function greenAction(
  overrides?: Partial<ActionLayerContext>
): ActionLayerContext {
  return {
    action_id: "ac-1",
    agent_id: "a-1",
    fortress_id: "f-1",
    time_of_action_state: "green",
    current_verifier_state: "green",
    policy_version: 1,
    action_at: new Date().toISOString(),
    ...overrides,
  };
}

describe("false-green guard: global badge fails closed", () => {
  // Sanity: a genuinely all-green context still earns green (no over-degrade).
  it("all-green context still earns green", () => {
    expect(deriveGlobalBadge(allGreenGlobal())).toBe("green");
  });

  // --- audit chain: a breached or absent audit chain must not read green ---
  it("audit chain red does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(allGreenGlobal({ audit_chain_state: "red" }));
    expect(badge).not.toBe("green");
    expect(badge).toBe("red");
  });

  it("audit chain offline does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ audit_chain_state: "offline" })
    );
    expect(badge).not.toBe("green");
  });

  // --- policy sync: red / offline were ignored entirely (only yellow read) ---
  it("policy sync red does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(allGreenGlobal({ policy_sync_state: "red" }));
    expect(badge).not.toBe("green");
    expect(badge).toBe("red");
  });

  it("policy sync offline does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ policy_sync_state: "offline" })
    );
    expect(badge).not.toBe("green");
  });

  // --- guardian: red / offline were ignored entirely (only yellow read) ---
  it("guardian red does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(allGreenGlobal({ guardian_state: "red" }));
    expect(badge).not.toBe("green");
    expect(badge).toBe("red");
  });

  it("guardian offline does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ guardian_state: "offline" })
    );
    expect(badge).not.toBe("green");
  });

  // --- corrupt / off-enum inputs must degrade, never fall through to green ---
  it("corrupt agent state does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ agent_badge_states: { "agent-x": CORRUPT } })
    );
    expect(badge).not.toBe("green");
    expect(BADGE_STATES).toContain(badge);
  });

  it("corrupt node state does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ node_states: { "node-x": CORRUPT } })
    );
    expect(badge).not.toBe("green");
    expect(BADGE_STATES).toContain(badge);
  });

  it("corrupt audit chain state does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ audit_chain_state: CORRUPT })
    );
    expect(badge).not.toBe("green");
  });
});

describe("false-green guard: agent badge fails closed", () => {
  it("all-green context still earns green", () => {
    expect(deriveAgentBadge(allGreenAgent())).toBe("green");
  });

  it("corrupt node attestation state does not render green (was false-green)", () => {
    const badge = deriveAgentBadge(
      allGreenAgent({ node_attestation_state: CORRUPT as never })
    );
    expect(badge).not.toBe("green");
    expect(BADGE_STATES).toContain(badge);
  });

  it("corrupt annex state does not render green (was false-green)", () => {
    const badge = deriveAgentBadge(
      allGreenAgent({ annex_states: { "annex-x": CORRUPT as never } })
    );
    expect(badge).not.toBe("green");
    expect(BADGE_STATES).toContain(badge);
  });

  it("offline annex does not render green (was false-green)", () => {
    const badge = deriveAgentBadge(
      allGreenAgent({ annex_states: { "annex-x": "offline" } })
    );
    expect(badge).not.toBe("green");
  });

  it("corrupt annex does not spoof the local_only steady state", () => {
    // A local_only node with a corrupt annex must NOT read as the clean
    // local_only steady state: the annex is unverifiable, so the agent
    // degrades to watch rather than presenting a trusted local_only badge.
    const badge = deriveAgentBadge(
      allGreenAgent({
        node_attestation_state: "local_only",
        annex_states: { "annex-x": CORRUPT as never },
      })
    );
    expect(badge).not.toBe("local_only");
    expect(badge).not.toBe("green");
  });
});

describe("false-green guard: action badge fails closed", () => {
  it("green then, green now still earns green", () => {
    expect(deriveActionBadge(greenAction())).toBe("green");
  });

  it("corrupt time-of-action state never escapes verbatim (was raw pass-through)", () => {
    const badge = deriveActionBadge(
      greenAction({ time_of_action_state: CORRUPT as never })
    );
    // Pre-fix: returned "purple" verbatim (an invalid, un-renderable badge
    // that silently drops the signal). Post-fix: a valid degraded state.
    expect(BADGE_STATES).toContain(badge);
    expect(badge).not.toBe("green");
  });

  it("green then, corrupt verifier now does not render green (was false-green)", () => {
    const badge = deriveActionBadge(
      greenAction({ current_verifier_state: CORRUPT as never })
    );
    expect(badge).not.toBe("green");
    expect(badge).toBe("yellow");
  });

  it("green then, offline verifier now degrades (no signal, not green)", () => {
    const badge = deriveActionBadge(
      greenAction({ current_verifier_state: "offline" })
    );
    expect(badge).not.toBe("green");
  });
});

describe("false-green guard: derivation only ever emits a known badge state", () => {
  // Exhaustive-ish fuzz over every enum value plus a corrupt value in every
  // slot, asserting the derivation output is always a member of BADGE_STATES
  // and that green is only ever reached from a wholly-nominal input set.
  const candidateStates = [...BADGE_STATES, "purple", ""] as unknown[];

  it("global derivation never emits an off-enum badge, and green implies nominal inputs", () => {
    for (const s of candidateStates) {
      const badge = deriveGlobalBadge(
        allGreenGlobal({
          audit_chain_state: s as never,
          policy_sync_state: s as never,
          guardian_state: s as never,
        })
      );
      expect(BADGE_STATES).toContain(badge);
      if (badge === "green") {
        // Green only when every varied input was itself a nominal state.
        expect(["green", "local_only"]).toContain(s);
      }
    }
  });

  it("agent derivation never emits an off-enum badge", () => {
    for (const s of candidateStates) {
      const badge = deriveAgentBadge(
        allGreenAgent({
          node_attestation_state: s as never,
          annex_states: { "annex-x": s as never },
        })
      );
      expect(BADGE_STATES).toContain(badge);
    }
  });

  it("action derivation never emits an off-enum badge", () => {
    for (const toa of candidateStates) {
      for (const now of candidateStates) {
        const badge = deriveActionBadge(
          greenAction({
            time_of_action_state: toa as never,
            current_verifier_state: now as never,
          })
        );
        expect(BADGE_STATES).toContain(badge);
      }
    }
  });
});

// -----------------------------------------------------------------------
// B4 finding #1: a signed attestation_failure event with a failure_mode must
// never store a badge state inconsistent with that failure_mode's catalog
// badge_result. fromSignedEvent only enum-validates resulting_state; without
// reconciliation, a signature-verified {failure_mode: <critical>, resulting_
// state: 'green'} event from a buggy or compromised producer stores GREEN
// with a failure explanation -- a false-green.
// -----------------------------------------------------------------------

function failureEvent(
  overrides?: Partial<AttestationEvent>
): AttestationEvent {
  return {
    event_id: "attest-b4f1",
    event_type: "attestation_failure_detected",
    signature_scheme: SIGNATURE_SCHEME_V1,
    target_layer: "global",
    scope_id: "f-1",
    resulting_state: "green",
    failure_mode: "sovereign_node_attestation_fail",
    emitted_at: new Date().toISOString(),
    explanation: "Sovereign node attestation failure",
    ...overrides,
  };
}

describe("false-green guard: signed failure event reconciles against catalog", () => {
  beforeEach(() => {
    clearAllBadgeStores();
  });

  it("failure_mode with a red catalog result overrides a claimed green (was false-green)", () => {
    // sovereign_node_attestation_fail -> catalog badge_result "red".
    // Pre-fix applyAttestationEvent trusted resulting_state and stored "green".
    const badge = applyAttestationEvent(failureEvent());
    expect(badge.state).not.toBe("green");
    expect(badge.state).toBe("red");
    // Explanation still points at the failure so the operator sees the cause.
    expect(badge.explanation_key).toBe(
      "failure.sovereign_node_attestation_fail"
    );
  });

  it("failure_mode with a yellow catalog result overrides a claimed green", () => {
    // tcb_drift_annex -> catalog badge_result "yellow".
    const badge = applyAttestationEvent(
      failureEvent({
        failure_mode: "tcb_drift_annex",
        target_layer: "per_agent",
        scope_id: "a-1",
        resulting_state: "green",
      })
    );
    expect(badge.state).not.toBe("green");
    expect(badge.state).toBe("yellow");
  });

  it("failure_mode with a local_only catalog result overrides a claimed green", () => {
    // local_only_mode -> catalog badge_result "local_only" (a nominal steady
    // state, but still NOT green when the event carries a failure_mode).
    const badge = applyAttestationEvent(
      failureEvent({
        failure_mode: "local_only_mode",
        target_layer: "per_agent",
        scope_id: "a-2",
        resulting_state: "green",
      })
    );
    expect(badge.state).not.toBe("green");
    expect(badge.state).toBe("local_only");
  });

  it("a producer that reports a WORSE state than catalog is honored (no over-relax)", () => {
    // policy_sync_lag -> catalog "yellow"; a producer legitimately escalating
    // to red must be kept, not softened back to the catalog baseline.
    const badge = applyAttestationEvent(
      failureEvent({
        failure_mode: "policy_sync_lag",
        resulting_state: "red",
      })
    );
    expect(badge.state).toBe("red");
  });

  it("any present failure_mode never yields green, even an unknown code", () => {
    const badge = applyAttestationEvent(
      failureEvent({
        // Cast: an off-catalog failure_mode from a buggy producer. The hard
        // floor must still refuse green.
        failure_mode: "not_a_real_code" as never,
        resulting_state: "green",
      })
    );
    expect(badge.state).not.toBe("green");
  });

  it("a clean recovery (no failure_mode) still renders green (no over-degrade)", () => {
    const badge = applyAttestationEvent(
      failureEvent({
        event_type: "attestation_recovered",
        failure_mode: undefined,
        resulting_state: "green",
        explanation: "Attestation recovered",
      })
    );
    expect(badge.state).toBe("green");
  });
});

// -----------------------------------------------------------------------
// B4 finding #2: deriveAgentBadge must positively EARN the local_only steady
// state. Pre-fix it returned local_only from a clean local_only node before
// checking identity_valid / policy_pinned / egress_enforcing, so those
// failures were silently dropped under a trusted-looking local_only badge.
// -----------------------------------------------------------------------

describe("false-green guard: local_only is positively earned (finding #2)", () => {
  // Sanity: a fully-nominal local_only agent still earns local_only.
  it("clean local_only agent still earns local_only (no over-degrade)", () => {
    const badge = deriveAgentBadge(
      allGreenAgent({ node_attestation_state: "local_only" })
    );
    expect(badge).toBe("local_only");
  });

  it("local_only node with INVALID identity is red, not local_only (was masked)", () => {
    const badge = deriveAgentBadge(
      allGreenAgent({
        node_attestation_state: "local_only",
        identity_valid: false,
      })
    );
    expect(badge).not.toBe("local_only");
    expect(badge).not.toBe("green");
    expect(badge).toBe("red");
  });

  it("local_only node with UNPINNED policy degrades, not local_only (was masked)", () => {
    const badge = deriveAgentBadge(
      allGreenAgent({
        node_attestation_state: "local_only",
        policy_pinned: false,
      })
    );
    expect(badge).not.toBe("local_only");
    expect(badge).not.toBe("green");
    expect(badge).toBe("yellow");
  });

  it("local_only node with NON-ENFORCING egress degrades, not local_only (was masked)", () => {
    const badge = deriveAgentBadge(
      allGreenAgent({
        node_attestation_state: "local_only",
        egress_enforcing: false,
      })
    );
    expect(badge).not.toBe("local_only");
    expect(badge).not.toBe("green");
    expect(badge).toBe("yellow");
  });
});

// -----------------------------------------------------------------------
// B4 finding #3: local_only is nominal only for posture fields (node / agent
// attestation state), NOT for the GLOBAL subsystem fields (audit chain,
// policy sync, guardian presence). Pre-fix classifyInput treated local_only
// as nominal for every field, so a local_only on a global subsystem earned a
// green fortress badge even though local_only is not a source-verified
// nominal state for those fortress-wide signals.
// -----------------------------------------------------------------------

describe("false-green guard: global subsystem local_only degrades (finding #3)", () => {
  it("audit chain local_only does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ audit_chain_state: "local_only" })
    );
    expect(badge).not.toBe("green");
    expect(badge).toBe("yellow");
  });

  it("policy sync local_only does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ policy_sync_state: "local_only" })
    );
    expect(badge).not.toBe("green");
    expect(badge).toBe("yellow");
  });

  it("guardian local_only does not render green (was false-green)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ guardian_state: "local_only" })
    );
    expect(badge).not.toBe("green");
    expect(badge).toBe("yellow");
  });

  // Legitimately-local_only fields must still work: a node or per-agent state
  // of local_only is a valid nominal steady state and must NOT over-degrade.
  it("node local_only remains nominal (posture field, not over-degraded)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ node_states: { "node-1": "local_only" } })
    );
    expect(badge).toBe("green");
  });

  it("per-agent local_only remains nominal (posture field, not over-degraded)", () => {
    const badge = deriveGlobalBadge(
      allGreenGlobal({ agent_badge_states: { "agent-1": "local_only" } })
    );
    expect(badge).toBe("green");
  });
});
