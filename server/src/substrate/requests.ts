/**
 * Plugin substrate — request envelope types (design §3.2; RFC §3.2, §4.1).
 *
 * Vendor-neutral request shapes the host marshals to a plugin. The host sends ONLY the
 * declared subset of fields (S4 enforces; S1 fixes the types). `arguments_hash` is a
 * KEYED correlation token, never a public content hash (§3.2b). `arguments_fields` is a
 * host-projected subset built by field-pick of granted JSON-pointers, never object-spread
 * of the request struct (§3.2a) — so a Low-tier plugin never receives it.
 *
 * S1 ships these as the contract type surface only; no marshaling/execution happens here.
 */

export type TrustLabel = "trusted" | "untrusted";

export interface RequestOrigin {
  channel: string;
  trust_label: TrustLabel;
}

/** Common envelope every hook request carries. */
export interface RequestEnvelope {
  request_id: string;
  /** Monotonic AND unpredictable-per-instance; the verdict must echo it (§3.1b). */
  nonce: string;
  agent_id: string;
  session_id: string;
  timestamp: string;
  origin: RequestOrigin;
}

/** policy_decision hook. */
export interface ToolCallRequest extends RequestEnvelope {
  hook_class: "policy_decision";
  tool_name: string;
  /** sha256(canonicalJSON(name, description, inputSchema)) — host-owned (§3.5). */
  tool_fingerprint: string;
  /** Keyed token (HMAC under a per-install host secret), NOT a public hash (§3.2b). */
  arguments_hash: string;
  /** Host-projected subset; present only under a granted Sensitive per-field grant (§3.2a). */
  arguments_fields?: Record<string, unknown>;
}

/** egress_decision hook. */
export interface EgressDecisionRequest extends RequestEnvelope {
  hook_class: "egress_decision";
  host: string;
  port: number;
  protocol: string;
}

/** ingress_content hook. */
export interface IngressContentRequest extends RequestEnvelope {
  hook_class: "ingress_content";
  content_length: number;
  content_hash: string;
  trust_label: TrustLabel;
  /** Raw content is Sensitive-tier; present only under a Tier-1 grant. */
  content?: string;
}

/** substrate_identity hook. */
export interface AttestationRequest extends RequestEnvelope {
  hook_class: "substrate_identity";
  subject_id: string;
  claim_type: string;
}

export type HookRequest =
  | ToolCallRequest
  | EgressDecisionRequest
  | IngressContentRequest
  | AttestationRequest;
