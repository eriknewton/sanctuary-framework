/**
 * Sanctuary Policy Engine — Types.
 *
 * Shape of the compiled policy artifact. The engine compiles plain-English
 * authoring into this deterministic structure; gates evaluate against the
 * compiled structure only. No LLM at gate time.
 */

import type {
  AutoTriggerTier,
  ChannelTemplateId,
  PolicySlot,
} from "./constants.js";

/** A single access grant from an agent on one slot to a counterparty. */
export interface SlotGrant {
  /** Counterparty agent_id. "*" means every agent in the mesh. */
  counterparty: string;
  /** Access verb. "read" / "write" / "subscribe" / "share". */
  action: string;
  /** Additional scoping constraints (tags, resource ids, etc.). */
  scope?: Record<string, unknown>;
  /** Optional maximum uses per day — engine treats undefined as no cap. */
  max_uses_per_day?: number;
}

/** Policy rule for one of the four canonical slots. */
export interface SlotRule {
  slot: PolicySlot;
  /**
   * "deny" = hermetic on this slot, no grants honored.
   * "grant" = evaluate `grants[]` with default-deny-on-no-match.
   */
  mode: "deny" | "grant";
  grants: SlotGrant[];
}

/**
 * Capability declarations that gate behaviors outside the four-slot surface.
 *
 * `concordia_commitment_classes` is the Agent Contract §7.1 capability gate:
 * a commitment-producing action is refused unless the relevant class appears
 * in this array.
 *
 * `honeypot_skill_ids` enumerates trip-wire skills the auto-trigger ladder
 * watches for — any invocation auto-freezes the agent at tier honeypot.
 *
 * `is_sentinel` per Walkthrough Key 11 LOCKED locks down inward-facing
 * defaults: no external network, no outbound tool calls to third-party APIs,
 * no credential access beyond the sentinel's own identity key.
 */
export interface CapabilityDeclarations {
  concordia_commitment_classes: string[];
  honeypot_skill_ids: string[];
  is_sentinel: boolean;
}

/**
 * Auto-trigger ladder configuration. v0.1 fixes two tiers at operator-only;
 * the flag shape is forward-compatible so v1.x can open them to "auto"
 * without changing the compiled policy schema.
 */
export interface AutoTriggerLadder {
  honeypot_auto_freeze: boolean;
  threshold_rule_action: "operator_approved" | "auto";
  ml_anomaly_action: "operator_approved" | "auto";
}

/**
 * Deterministic, versioned, signed-outside policy artifact. `policy_blob` on
 * the mesh's PolicyUpdatePayload is base64url(canonicalizeToBytes(this)).
 */
export interface CompiledPolicy {
  schema_version: "0.1";
  agent_id: string;
  fortress_id: string;
  /** Per-agent monotonic version. */
  policy_version: number;
  /** Optional parent_version for fork/rollback detection. */
  parent_version?: number;
  /**
   * The four slots, exactly. Runtime validation rejects any other keys and
   * rejects missing ones.
   */
  slots: {
    memory: SlotRule;
    credentials: SlotRule;
    plans: SlotRule;
    outputs: SlotRule;
  };
  capabilities: CapabilityDeclarations;
  auto_trigger_ladder: AutoTriggerLadder;
  /** The English the operator wrote. Retained verbatim for audit and display. */
  source_english: string;
  /** ISO8601 UTC. */
  compiled_at: string;
}

/**
 * Identifying context for the evaluating node. The signing key is used to
 * sign the gate receipt. Kept out of CompiledPolicy so the blob is
 * deterministic regardless of which node evaluates it.
 */
export interface GateContext {
  /** Compiled policy pinned for the agent. `null` ⇒ hermetic null policy. */
  policy: CompiledPolicy | null;
  /** Ed25519 private key of the evaluating node. Used ONLY to sign receipts. */
  nodeSigningKey: Uint8Array;
  nodeId: string;
  fortressId: string;
}

/** Input to a slot-gate evaluation. */
export interface GateRequest {
  /** Caller agent making the slot access attempt. */
  agent_id: string;
  /** Counterparty being accessed. May be "*" when enumerating. */
  counterparty: string;
  /** "read" / "write" / "subscribe" / "share" — matched literally against grants. */
  action: string;
  /** Scope constraints the caller is claiming. */
  scope?: Record<string, unknown>;
  /**
   * Honeypot hint: if the caller names a skill_id here, the honeypot tier of
   * the auto-trigger ladder fires before any slot rule evaluation.
   */
  invoked_skill_id?: string;
}

/** Gate decision + signed receipt. */
export interface GateResult {
  decision: "allow" | "deny" | "operator_approval_required";
  reason_code: string;
  receipt: GateReceipt;
  /** Human-legible explanation string for the console. */
  explanation: string;
}

/**
 * Signed gate receipt. Records the decision and binds it to the evaluating
 * node. Distinct from Concordia commitment receipts — this receipt does NOT
 * sign a commitment; it signs "I, this node, evaluated this gate and
 * returned this decision against this pinned policy version."
 */
export interface GateReceipt {
  receipt_id: string;
  decision: "allow" | "deny" | "operator_approval_required";
  slot: PolicySlot | "commitment_boundary";
  agent_id: string;
  counterparty?: string;
  action: string;
  invoked_skill_id?: string;
  policy_version: number | null;
  reason_code: string;
  fortress_id: string;
  /** Evaluating node. Receiver trusts a receipt only if this chains to pinned fortress-master. */
  evaluating_node_id: string;
  /** Tier of the auto-trigger ladder that fired, if any. */
  ladder_tier_fired?: AutoTriggerTier;
  timestamp: string;
  /** Ed25519 signature over canonicalize(receipt minus signature). */
  signature: string;
}

/** Channel-template parameters common to all five templates. */
export interface ChannelTemplateParams {
  /** Caller agent whose policy this channel opens on. */
  agent_id: string;
  /** Counterparty the channel opens TO. */
  counterparty: string;
  /** Fortress the agents live in. */
  fortress_id: string;
  /** Monotonic per-agent version the new signed event carries. */
  policy_version: number;
  /** Optional parent_version for rollback detection. */
  parent_version?: number;
  /** Optional scope constraints per-slot. */
  scope?: Record<string, unknown>;
  /** Optional pre-existing compiled policy to merge into. */
  merge_into?: CompiledPolicy;
}

/** Factory shape for channel-template implementations. */
export type ChannelTemplateFactory = (
  params: ChannelTemplateParams
) => CompiledPolicy;

export interface ChannelTemplateRegistryEntry {
  id: ChannelTemplateId;
  /** Short human-readable label for the console. */
  label: string;
  /** English description of what the template opens. */
  description: string;
  factory: ChannelTemplateFactory;
}
