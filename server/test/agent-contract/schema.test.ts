/**
 * Agent Contract v0.1 — Schema validation tests.
 *
 * Covers spec §3 (Agent Card) and §6 (usage event), plus the §2.8 lifecycle
 * event, §2.9 attestation, §7.1 commitment proposal, and §2.3 harness
 * envelope shapes.
 *
 * Every positive case exercises a real shape that round-trips through
 * validation; every negative case deletes, corrupts, or adds a single field
 * to prove the validator catches it.
 */

import { describe, it, expect } from "vitest";
import {
  AGENT_CONTRACT_VERSION,
  CAPABILITY_KINDS,
  EVENT_CLASSES,
  HARNESS_TIERS,
  MODEL_PROVIDERS,
  SIGNATURE_SCHEME_V1,
} from "../../src/agent-contract/constants.js";
import {
  AgentCardSchemaError,
  UsageEventSchemaError,
  AgentContractError,
} from "../../src/agent-contract/errors.js";
import {
  validateAgentCard,
  validateAttestation,
  validateCapability,
  validateCommitmentProposal,
  validateHarnessEnvelope,
  validateLifecycleEvent,
  validateUsageEvent,
} from "../../src/agent-contract/schema.js";

function baseCard(): Record<string, unknown> {
  return {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    agent_id: "agent-alpha",
    fortress_id: "fortress-1",
    tier: "B",
    harness_id: "cline",
    model_provider: "anthropic",
    model_id: "claude-opus-4-7",
    agent_pubkey: "abc123XYZ-_",
    policy_version_hash: "h4sh0UTc0me__",
    policy_version: 1,
    attestation_endpoint: "http://127.0.0.1:3501/attestations",
    capabilities: [
      { kind: "read-slot", target: "memory" },
      { kind: "tool-call", target: "filesystem/read*" },
    ],
    issued_at: "2026-04-21T22:00:00Z",
  };
}

describe("Agent Card schema (§3)", () => {
  it("accepts a well-formed card", () => {
    const card = validateAgentCard(baseCard());
    expect(card.agent_id).toBe("agent-alpha");
    expect(card.tier).toBe("B");
    expect(card.capabilities).toHaveLength(2);
  });

  it("rejects unknown top-level keys", () => {
    const c = baseCard();
    c.rogue_field = "nope";
    expect(() => validateAgentCard(c)).toThrow(AgentCardSchemaError);
  });

  it("rejects wrong schema_version", () => {
    const c = baseCard();
    c.schema_version = "9.9";
    expect(() => validateAgentCard(c)).toThrow(/schema_version/);
  });

  it("rejects a non-v1 signature_scheme", () => {
    const c = baseCard();
    c.signature_scheme = "ml-dsa-v1";
    expect(() => validateAgentCard(c)).toThrow(/signature_scheme/);
  });

  it("rejects unknown tier", () => {
    const c = baseCard();
    c.tier = "Z";
    expect(() => validateAgentCard(c)).toThrow(/tier/);
  });

  it("accepts every tier in HARNESS_TIERS", () => {
    for (const t of HARNESS_TIERS) {
      const c = baseCard();
      c.tier = t;
      expect(() => validateAgentCard(c)).not.toThrow();
    }
  });

  it("accepts every model_provider in MODEL_PROVIDERS", () => {
    for (const p of MODEL_PROVIDERS) {
      const c = baseCard();
      c.model_provider = p;
      expect(() => validateAgentCard(c)).not.toThrow();
    }
  });

  it("rejects a missing ISO8601 Z on issued_at", () => {
    const c = baseCard();
    c.issued_at = "2026-04-21T22:00:00+00:00";
    expect(() => validateAgentCard(c)).toThrow(/issued_at/);
  });

  it("rejects non-integer policy_version", () => {
    const c = baseCard();
    c.policy_version = 1.5;
    expect(() => validateAgentCard(c)).toThrow(/policy_version/);
  });

  it("rejects a non-base64url agent_pubkey", () => {
    const c = baseCard();
    c.agent_pubkey = "has spaces";
    expect(() => validateAgentCard(c)).toThrow(/agent_pubkey/);
  });

  it("rejects an empty attestation_endpoint", () => {
    const c = baseCard();
    c.attestation_endpoint = "";
    expect(() => validateAgentCard(c)).toThrow(/attestation_endpoint/);
  });

  it("accepts every capability kind", () => {
    for (const k of CAPABILITY_KINDS) {
      const cap = validateCapability({ kind: k, target: "x" });
      expect(cap.kind).toBe(k);
    }
  });

  it("rejects unknown capability kind", () => {
    expect(() =>
      validateCapability({ kind: "do-anything", target: "x" })
    ).toThrow(AgentCardSchemaError);
  });

  it("rejects capability with empty target", () => {
    expect(() => validateCapability({ kind: "tool-call", target: "" })).toThrow(
      /target/
    );
  });
});

describe("Usage event schema (§6)", () => {
  function base(): Record<string, unknown> {
    return {
      schema_version: AGENT_CONTRACT_VERSION,
      signature_scheme: SIGNATURE_SCHEME_V1,
      usage_event_id: "01HX9-1",
      agent_id: "agent-alpha",
      fortress_id: "fortress-1",
      event_class: "tool_call",
      capability_kind: "tool-call",
      capability_target: "filesystem/read",
      input_hash: "AAAA",
      output_hash: "BBBB",
      policy_version: 1,
      policy_version_hash: "hashy-hash",
      attestation_state: "present",
      emitted_at: "2026-04-21T22:00:00Z",
    };
  }

  /** Variant without capability_kind — for non-tool_call event classes. */
  function baseNoKind(event_class: string): Record<string, unknown> {
    const b = base();
    delete b.capability_kind;
    b.event_class = event_class;
    return b;
  }

  it("accepts a well-formed usage event", () => {
    const ev = validateUsageEvent(base());
    expect(ev.event_class).toBe("tool_call");
    expect(ev.capability_kind).toBe("tool-call");
    expect(ev.attestation_state).toBe("present");
  });

  it("rejects unknown keys", () => {
    const b = base();
    b.unexpected = "x";
    expect(() => validateUsageEvent(b)).toThrow(UsageEventSchemaError);
  });

  it("rejects unknown attestation_state", () => {
    const b = base();
    b.attestation_state = "pending";
    expect(() => validateUsageEvent(b)).toThrow(/attestation_state/);
  });

  it("rejects non-integer policy_version", () => {
    const b = base();
    b.policy_version = 1.5;
    expect(() => validateUsageEvent(b)).toThrow(/policy_version/);
  });

  it("accepts 'degraded' and 'unavailable' attestation_state", () => {
    for (const s of ["degraded", "unavailable"]) {
      const b = base();
      b.attestation_state = s;
      expect(() => validateUsageEvent(b)).not.toThrow();
    }
  });

  // ─── event_class coverage per spec §6 ───────────────────────────────────

  it("enumerates all 31 event_class values from spec §6", () => {
    // Tripwire: if this count changes, the spec enum changed too and every
    // downstream consumer (audit viewer, Verascore ingest, attestation UX)
    // needs review.
    expect(EVENT_CLASSES).toHaveLength(31);
  });

  it("accepts a lifecycle event_class (launched)", () => {
    const ev = validateUsageEvent(baseNoKind("launched"));
    expect(ev.event_class).toBe("launched");
  });

  it("accepts a tool event_class (tool_call) with capability_kind", () => {
    const ev = validateUsageEvent(base());
    expect(ev.event_class).toBe("tool_call");
  });

  it("accepts an egress event_class (egress_request)", () => {
    const ev = validateUsageEvent(baseNoKind("egress_request"));
    expect(ev.event_class).toBe("egress_request");
  });

  it("accepts a gate event_class (gate_denied)", () => {
    const ev = validateUsageEvent(baseNoKind("gate_denied"));
    expect(ev.event_class).toBe("gate_denied");
  });

  it("accepts a policy event_class (policy_pinned)", () => {
    const ev = validateUsageEvent(baseNoKind("policy_pinned"));
    expect(ev.event_class).toBe("policy_pinned");
  });

  it("accepts a capability-management event_class (capability_declared)", () => {
    const ev = validateUsageEvent(baseNoKind("capability_declared"));
    expect(ev.event_class).toBe("capability_declared");
  });

  it("accepts an envelope event_class (envelope_sent)", () => {
    const ev = validateUsageEvent(baseNoKind("envelope_sent"));
    expect(ev.event_class).toBe("envelope_sent");
  });

  it("accepts an attestation event_class (attestation_emitted)", () => {
    const ev = validateUsageEvent(baseNoKind("attestation_emitted"));
    expect(ev.event_class).toBe("attestation_emitted");
  });

  it("accepts a commitment event_class (commitment_proposed)", () => {
    const ev = validateUsageEvent(baseNoKind("commitment_proposed"));
    expect(ev.event_class).toBe("commitment_proposed");
  });

  it("rejects usage events missing event_class", () => {
    const b = base();
    delete b.event_class;
    expect(() => validateUsageEvent(b)).toThrow(/event_class/);
  });

  it("rejects unknown event_class values", () => {
    const b = baseNoKind("not_a_real_class");
    expect(() => validateUsageEvent(b)).toThrow(/event_class/);
  });

  it("rejects capability_kind set when event_class !== 'tool_call'", () => {
    const b = base();
    b.event_class = "gate_denied";
    // capability_kind still present from base()
    expect(() => validateUsageEvent(b)).toThrow(/capability_kind/);
  });
});

describe("Lifecycle event schema (§2.8)", () => {
  function base(): Record<string, unknown> {
    return {
      schema_version: AGENT_CONTRACT_VERSION,
      signature_scheme: SIGNATURE_SCHEME_V1,
      agent_id: "a",
      fortress_id: "f",
      from_state: "launched",
      to_state: "paused",
      reason: "operator pause",
      emitted_at: "2026-04-21T22:00:00Z",
    };
  }

  it("accepts a well-formed event", () => {
    const ev = validateLifecycleEvent(base());
    expect(ev.to_state).toBe("paused");
  });

  it("accepts 'uninstantiated' as from_state", () => {
    const b = base();
    b.from_state = "uninstantiated";
    b.to_state = "launched";
    expect(() => validateLifecycleEvent(b)).not.toThrow();
  });

  it("rejects unknown to_state", () => {
    const b = base();
    b.to_state = "terminated";
    expect(() => validateLifecycleEvent(b)).toThrow(AgentContractError);
  });

  it("rejects non-base64url checkpoint_hash", () => {
    const b = base();
    b.checkpoint_hash = "has spaces";
    expect(() => validateLifecycleEvent(b)).toThrow(/checkpoint_hash/);
  });

  it("rejects malformed guardian_quorum", () => {
    const b = base();
    b.guardian_quorum = [{ guardian_pubkey: "", signature: "abc" }];
    expect(() => validateLifecycleEvent(b)).toThrow(/guardian_quorum/);
  });
});

describe("Attestation schema (§2.9)", () => {
  function base(): Record<string, unknown> {
    return {
      schema_version: AGENT_CONTRACT_VERSION,
      signature_scheme: SIGNATURE_SCHEME_V1,
      attestation_id: "att-1",
      agent_id: "a",
      fortress_id: "f",
      usage_event_id: "u-1",
      source: "harness_self_report",
      attested_hash: "AAAA",
      emitted_at: "2026-04-21T22:00:00Z",
    };
  }

  it("accepts a well-formed attestation", () => {
    const att = validateAttestation(base());
    expect(att.source).toBe("harness_self_report");
  });

  it("rejects unknown source", () => {
    const b = base();
    b.source = "rando";
    expect(() => validateAttestation(b)).toThrow(/source/);
  });
});

describe("Commitment proposal schema (§7.1)", () => {
  function base(): Record<string, unknown> {
    return {
      schema_version: AGENT_CONTRACT_VERSION,
      signature_scheme: SIGNATURE_SCHEME_V1,
      proposal_id: "p-1",
      agent_id: "a",
      fortress_id: "f",
      commitment_class: "task-delegate",
      counterparty: "peer-agent",
      bounded_scope: {
        deliverable: "ship draft by tuesday",
        deadline_or_terminal: "2026-04-28T17:00:00Z",
        budget_ref: "budget-2026-Q2",
      },
      policy_version: 1,
      policy_version_hash: "hash",
      emitted_at: "2026-04-21T22:00:00Z",
      gate_receipt_id: "r-1",
    };
  }

  it("accepts a well-formed proposal", () => {
    const p = validateCommitmentProposal(base());
    expect(p.counterparty).toBe("peer-agent");
  });

  it("rejects missing bounded_scope field", () => {
    const b = base();
    (b.bounded_scope as Record<string, unknown>).deliverable = "";
    expect(() => validateCommitmentProposal(b)).toThrow(/deliverable/);
  });
});

describe("Harness envelope schema (§2.3)", () => {
  function base(): Record<string, unknown> {
    return {
      schema_version: AGENT_CONTRACT_VERSION,
      signature_scheme: SIGNATURE_SCHEME_V1,
      envelope_id: "e-1",
      direction: "harness_out",
      agent_id: "a",
      fortress_id: "f",
      capability_kind: "tool-call",
      capability_target: "filesystem/read",
      body: { key: "value" },
      body_hash: "hashbytes",
      policy_version: 1,
      sender_claim: {
        claimant: "a",
        asserted_at: "2026-04-21T22:00:00Z",
      },
      wrapped_at: "2026-04-21T22:00:00Z",
    };
  }

  it("accepts a well-formed envelope", () => {
    const env = validateHarnessEnvelope(base());
    expect(env.direction).toBe("harness_out");
  });

  it("rejects unknown direction", () => {
    const b = base();
    b.direction = "both";
    expect(() => validateHarnessEnvelope(b)).toThrow(/direction/);
  });

  it("rejects missing sender_claim", () => {
    const b = base();
    delete b.sender_claim;
    expect(() => validateHarnessEnvelope(b)).toThrow(/sender_claim/);
  });

  it("accepts a receiver_check stamp", () => {
    const b = base();
    b.receiver_check = { decision: "allow", reason_code: "ok" };
    expect(() => validateHarnessEnvelope(b)).not.toThrow();
  });

  it("rejects receiver_check with unknown decision", () => {
    const b = base();
    b.receiver_check = { decision: "maybe", reason_code: "?" };
    expect(() => validateHarnessEnvelope(b)).toThrow(/decision/);
  });
});
