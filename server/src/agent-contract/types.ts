/**
 * Sanctuary Agent Contract v0.1 — Types.
 *
 * Wire shapes exactly matching the JSON Schemas in spec §3 (Agent Card) and
 * §6 (usage event). Every signed emission in this module carries
 * `signature_scheme: "ed25519-v1"` as its crypto-agility hinge.
 *
 * Spec: Review/Sanctuary/Agent_Contract_V0.1_Spec_2026-04-21.md
 */

import type {
  AgentSubkeyPurpose,
  CapabilityKind,
  CommitmentClass,
  EventClass,
  HarnessTier,
  LifecycleState,
  ModelProvider,
  SignatureScheme,
} from "./constants.js";

// ═══════════════════════════════════════════════════════════════════════
// §3 Agent Card
// ═══════════════════════════════════════════════════════════════════════

/**
 * Single capability declaration on an Agent Card.
 *
 * `kind` gates the action class; `target` is the specific resource
 * (slot name, tool name, URL prefix, etc.); `constraints` further scope the
 * grant (per-day caps, allowed domains, etc.).
 */
export interface AgentCardCapability {
  kind: CapabilityKind;
  target: string;
  constraints?: Record<string, unknown>;
}

/**
 * Agent Card — the signed declaration of what an agent is and what it may do.
 *
 * Issued by the broker at launch via mesh `packSignedEvent`. The envelope
 * carries this as its payload and provides the Ed25519 signature by the
 * broker's per-node key. The card itself embeds `signature_scheme` so a
 * v1.x PQ-hybrid upgrade is readable by v1.0 verifiers.
 */
export interface AgentCard {
  schema_version: "0.1";
  signature_scheme: SignatureScheme;
  agent_id: string;
  fortress_id: string;
  /** Harness tier per §5 — A / B / C. */
  tier: HarnessTier;
  /** Harness label for display, e.g. "cline", "claude-code", "mastra". */
  harness_id: string;
  /** Model provider per §3. */
  model_provider: ModelProvider;
  /** Model identifier as reported by the harness or pinned by the operator. */
  model_id: string;
  /** Ed25519 public key (base64url) bound to this agent for its lifetime. */
  agent_pubkey: string;
  /**
   * Hash of the pinned policy artifact. Every signed action references this
   * so an auditor can confirm the agent operated under the pinned version.
   */
  policy_version_hash: string;
  /** Integer policy_version pinned at launch — set to -1 for hermetic null-policy launches. */
  policy_version: number;
  /** Attestation endpoint for per-action attestation fetch per §2.9. Operator-local URL. */
  attestation_endpoint: string;
  /** Declared capabilities. Undeclared → fail closed at the broker per §2.4. */
  capabilities: AgentCardCapability[];
  /** ISO8601 UTC issuance timestamp. */
  issued_at: string;
  /** Optional ISO8601 UTC expiry. Absent ⇒ no fixed expiry. */
  expires_at?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §6 Usage event
// ═══════════════════════════════════════════════════════════════════════

/**
 * Usage event — emitted for every contract-bearing action.
 *
 * One event per action. Append-only. Envelope-signed by the emitting node's
 * per-node key (the same node that issued the Agent Card). Carries its own
 * `signature_scheme` for crypto-agility.
 */
export interface UsageEvent {
  schema_version: "0.1";
  signature_scheme: SignatureScheme;
  usage_event_id: string;
  agent_id: string;
  fortress_id: string;
  /**
   * Event classification per spec §6. Primary discriminator for downstream
   * consumers — covers lifecycle, tool, egress, gate, policy, capability,
   * envelope, attestation, commitment, mandate, budget, and sentinel classes.
   */
  event_class: EventClass;
  /**
   * Capability kind invoked. REQUIRED when `event_class === "tool_call"`;
   * MUST be absent for every other `event_class`. Downstream consumers that
   * need a capability-kind dimension on non-tool-call events should look at
   * `event_class` + the event-specific subject fields instead.
   */
  capability_kind?: CapabilityKind;
  /** Specific target — slot name, tool name, URL, counterparty, etc. */
  capability_target: string;
  /** SHA-256 (base64url) of the canonicalized action input. Bytes-level integrity. */
  input_hash: string;
  /** SHA-256 (base64url) of the canonicalized action output. */
  output_hash: string;
  /** Policy version pinned when this action ran — equal to card.policy_version. */
  policy_version: number;
  policy_version_hash: string;
  /** Attestation state per §2.9. `"present"` = attestation signed; `"degraded"` = degrade-not-destroy applied. */
  attestation_state: "present" | "degraded" | "unavailable";
  /** Wall-clock ISO8601 UTC. */
  emitted_at: string;
  /**
   * Causal references back to prior usage events that produced this one. Each
   * entry points at a specific predecessor by `event_class` + `usage_event_id`.
   * Spec §6 requires this for chain-of-causation reconstruction (commitment
   * proposal then tool_call, etc.). Omitted when no causal link exists.
   *
   * `event_type` MUST be one of EVENT_CLASSES; `event_id` MUST be a non-empty
   * string. Schema validation enforces both.
   */
  references?: Array<{ event_type: EventClass; event_id: string }>;
  /** Optional extension — operator-specific fields. Reserved keys rejected at envelope pack time. */
  extension?: Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════
// §2.8 Lifecycle event
// ═══════════════════════════════════════════════════════════════════════

/**
 * Lifecycle event — signed emission for each transition. A `retired` event
 * seals the audit log segment for this agent; a `revoked` event is
 * guardian-initiated and force-closes outstanding work.
 */
export interface LifecycleEvent {
  schema_version: "0.1";
  signature_scheme: SignatureScheme;
  agent_id: string;
  fortress_id: string;
  from_state: LifecycleState | "uninstantiated";
  to_state: LifecycleState;
  /** Reason string for display + audit. */
  reason: string;
  /** Checkpoint hash for `checkpointed` / `resumed` transitions. */
  checkpoint_hash?: string;
  emitted_at: string;
  /** For `revoked` events: guardian quorum signatures per Walkthrough Key 13. */
  guardian_quorum?: Array<{ guardian_pubkey: string; signature: string }>;
}

// ═══════════════════════════════════════════════════════════════════════
// §2.9 Attestation
// ═══════════════════════════════════════════════════════════════════════

/**
 * Per-action attestation shape. Bound to a specific usage event so an
 * external verifier can fetch `attestation_endpoint/{usage_event_id}` and
 * receive this blob.
 */
export interface Attestation {
  schema_version: "0.1";
  signature_scheme: SignatureScheme;
  attestation_id: string;
  agent_id: string;
  fortress_id: string;
  /** Usage event this attestation binds to. */
  usage_event_id: string;
  /** Attestation type — `harness_self_report` (agent's word), `proxy_canonical` (broker-observed). */
  source: "harness_self_report" | "proxy_canonical";
  /** Hash of the attested body — the harness-reported payload + proxy-observed envelope. */
  attested_hash: string;
  emitted_at: string;
  /** Absent means attestation failed; downstream consumers apply degrade-not-destroy per §2.9. */
  attested_payload?: Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════
// §7.1 Commitment boundary proposal
// ═══════════════════════════════════════════════════════════════════════

/**
 * Commitment proposal event — emitted only when all four §7.1 conditions
 * hold. The policy engine's `evaluateCommitmentBoundary` decides; this
 * module proposes. A Concordia sidecar downstream takes over for the
 * negotiation cycle.
 */
export interface CommitmentProposal {
  schema_version: "0.1";
  signature_scheme: SignatureScheme;
  proposal_id: string;
  agent_id: string;
  fortress_id: string;
  commitment_class: CommitmentClass | string;
  /** Named counterparty. "*" / broadcast forms fail §7.1 condition 2. */
  counterparty: string;
  /** §7.1 condition 3 triplet — all three non-empty or the gate refuses. */
  bounded_scope: {
    deliverable: string;
    deadline_or_terminal: string;
    budget_ref: string;
  };
  policy_version: number;
  policy_version_hash: string;
  emitted_at: string;
  /** Forward ref: the gate-receipt issued by the policy engine at this call. */
  gate_receipt_id: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §2.2 Per-agent identity binding
// ═══════════════════════════════════════════════════════════════════════

/**
 * Per-agent identity record — holds the agent's Ed25519 public key plus the
 * enumerated HKDF-derived subkey purposes. The raw private key is never
 * stored in this shape; it is encrypted by the state-store layer and unwrapped
 * transiently for signing.
 */
export interface AgentIdentityBinding {
  agent_id: string;
  fortress_id: string;
  agent_pubkey: string;
  /** Subkey purposes that have been derived. Auditor-readable. */
  derived_subkey_purposes: AgentSubkeyPurpose[];
  bound_at: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §2.3 Harness I/O envelope (Sanctuary envelope)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Sanctuary envelope for harness I/O per §2.3. Rides on top of whatever
 * transport the harness speaks (MCP stdio, subprocess stdin, HTTP). Every
 * message in or out of the harness is wrapped; both sides authorize per
 * §2.3 (sender's claim + receiver's policy check).
 */
export interface HarnessEnvelope<Body = unknown> {
  schema_version: "0.1";
  signature_scheme: SignatureScheme;
  envelope_id: string;
  direction: "harness_in" | "harness_out";
  agent_id: string;
  fortress_id: string;
  /** Capability kind the wrapped body invokes. */
  capability_kind: CapabilityKind;
  capability_target: string;
  /** Body — opaque to the envelope. */
  body: Body;
  /** SHA-256 (base64url) of canonicalize(body). */
  body_hash: string;
  /** Policy version pinned at the time of wrap. */
  policy_version: number;
  /** Sender's claim — caller's assertion that the envelope is authorized. */
  sender_claim: {
    claimant: string;
    asserted_at: string;
  };
  /** Receiver's policy check result — populated on unwrap by the receiver. */
  receiver_check?: {
    decision: "allow" | "deny";
    reason_code: string;
    gate_receipt_id?: string;
  };
  wrapped_at: string;
}
