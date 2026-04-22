/**
 * Sanctuary Composition v1.0 -- Types
 *
 * CompositionConfig, SidecarRequest/Response, ConcordiaReceipt,
 * VerascoreSignal, MandateRef, CompositionDegradeState.
 *
 * Architecture walkthrough: Q4 (Concordia intra-mesh composition)
 * Scope lock: WP-MVP-10
 */

import type {
  CompositionEventType,
  SignatureScheme,
  VerascoreScope,
} from "./constants.js";

// -----------------------------------------------------------------------
// Composition config (fortress-level toggle)
// -----------------------------------------------------------------------

/**
 * Fortress-level composition configuration.
 * Default: composition_enabled = false (structural moat invariant).
 */
export interface CompositionConfig {
  /** Master toggle. false = zero composition code paths reachable. */
  composition_enabled: boolean;
  /** Verascore scope default for auto-hook. "private" = operator-private. */
  verascore_default_scope: VerascoreScope;
  /** Path to the Python sidecar script. */
  sidecar_script_path: string;
  /** Path to the Python interpreter (within the venv). */
  python_path: string;
  /** Sidecar spawn timeout in ms. */
  sidecar_spawn_timeout_ms: number;
  /** Sidecar RPC call timeout in ms. */
  sidecar_rpc_timeout_ms: number;
  /** Sidecar restart initial delay in ms. */
  sidecar_restart_initial_delay_ms: number;
  /** Sidecar restart max delay in ms. */
  sidecar_restart_max_delay_ms: number;
  /** Sidecar restart backoff multiplier. */
  sidecar_restart_backoff_multiplier: number;
  /** Max consecutive sidecar crashes before steady degraded. */
  sidecar_max_consecutive_crashes: number;
  /** Max replay queue depth. */
  replay_queue_max_depth: number;
}

// -----------------------------------------------------------------------
// JSON-RPC sidecar protocol
// -----------------------------------------------------------------------

/**
 * JSON-RPC 2.0 request to the Concordia Python sidecar.
 */
export interface SidecarRequest {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params: Record<string, unknown>;
}

/**
 * JSON-RPC 2.0 response from the sidecar.
 */
export interface SidecarResponse {
  jsonrpc: "2.0";
  id: number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

// -----------------------------------------------------------------------
// Concordia receipt (packed by sidecar from Sanctuary commitment event)
// -----------------------------------------------------------------------

/**
 * A Concordia receipt produced by the sidecar from a Sanctuary commitment event.
 *
 * This is the composition-layer shape, not the raw Concordia SDK shape.
 * The sidecar maps between the two.
 */
export interface ConcordiaReceipt {
  /** Unique receipt ID (from the sidecar). */
  receipt_id: string;
  /** Schema URN (urn:concordia:schema:receipt:v1). */
  schema_urn: string;
  /** Source Sanctuary signed-event ID that triggered this receipt. */
  source_event_id: string;
  /** Source event type (e.g., commitment_boundary allow). */
  source_event_type: string;
  /** Agent ID that emitted the commitment. */
  agent_id: string;
  /** Counterparty agent ID. */
  counterparty_id: string;
  /** Commitment class from the policy engine. */
  commitment_class: string;
  /** References graph (Concordia references[] shape). */
  references: ConcordiaReference[];
  /** Ed25519 signature over canonical receipt (from sidecar). */
  signature: string;
  /** Signature scheme (must be ed25519-v1 at v1.0). */
  signature_scheme: SignatureScheme;
  /** ISO8601 UTC timestamp. */
  packed_at: string;
  /** Concordia attestation metadata (behavioral signals only, no raw terms). */
  attestation_metadata?: Record<string, unknown>;
}

/**
 * A reference entry in the Concordia references[] graph.
 * Type-safe wrapper over the Concordia SDK shape.
 */
export interface ConcordiaReference {
  /** Reference type: receipt, chain_session, predicate, or mandate. */
  ref_type: "receipt" | "chain_session" | "predicate" | "mandate";
  /** Referenced artifact ID. */
  ref_id: string;
  /** Relationship: supersedes, extends, fulfills, or references. */
  relationship: "supersedes" | "extends" | "fulfills" | "references";
  /** Optional metadata. */
  metadata?: Record<string, unknown>;
}

// -----------------------------------------------------------------------
// Verascore signal (auto-published on commitment close)
// -----------------------------------------------------------------------

/**
 * A reputation signal published to Verascore on commitment close.
 * Default scope: operator-private. Public requires explicit opt-in.
 */
export interface VerascoreSignal {
  /** Unique signal ID. */
  signal_id: string;
  /** Source receipt ID this signal derives from. */
  source_receipt_id: string;
  /** Agent ID. */
  agent_id: string;
  /** Fortress ID. */
  fortress_id: string;
  /** Signal type (commitment-close at v1.0). */
  signal_type: "commitment_close";
  /** Publish scope: private or public. */
  scope: VerascoreScope;
  /** Ed25519 signature over canonical signal. */
  signature: string;
  /** Signature scheme (ed25519-v1). */
  signature_scheme: SignatureScheme;
  /** ISO8601 UTC. */
  published_at: string;
  /** Behavioral metrics (no raw deal terms; privacy invariant). */
  behavioral_metrics: {
    commitment_class: string;
    counterparty_count: number;
    references_count: number;
  };
}

// -----------------------------------------------------------------------
// Mandate reference (Concordia v0.4.0 Mandate support)
// -----------------------------------------------------------------------

/**
 * A mandate reference for delegation chain support.
 * Wraps the Concordia Mandate verification result.
 */
export interface MandateVerificationResult {
  /** Whether the mandate is valid. */
  valid: boolean;
  /** Mandate ID (URN). */
  mandate_id: string;
  /** Schema URN. */
  schema_urn: string;
  /** Issuer DID or agent_id. */
  issuer: string;
  /** Subject DID or agent_id. */
  subject: string;
  /** Delegation chain depth (max 5 at v1.0). */
  delegation_depth: number;
  /** Mandate status. */
  status: "active" | "expired" | "revoked" | "suspended";
  /** Verification checks performed. */
  checks: {
    signature_valid: boolean;
    chain_valid: boolean;
    not_expired: boolean;
    not_revoked: boolean;
    constraints_valid: boolean;
  };
  /** ISO8601 UTC. */
  verified_at: string;
  /** Signature scheme. */
  signature_scheme: SignatureScheme;
}

// -----------------------------------------------------------------------
// Composition degrade state
// -----------------------------------------------------------------------

/**
 * Composition degrade state. Tracks sidecar health and composition
 * subsystem availability for the attestation badge surface.
 */
export interface CompositionDegradeState {
  /** Whether composition is in degraded mode. */
  degraded: boolean;
  /** Reason for degradation (empty string if not degraded). */
  reason: string;
  /** Number of consecutive sidecar crashes. */
  consecutive_crashes: number;
  /** Whether the replay queue is active (events queued for sidecar recovery). */
  replay_queue_active: boolean;
  /** Number of events in the replay queue. */
  replay_queue_depth: number;
  /** ISO8601 UTC of last sidecar crash (null if never). */
  last_crash_at: string | null;
  /** ISO8601 UTC of last successful sidecar operation (null if never). */
  last_success_at: string | null;
  /** Sidecar process state. */
  sidecar_state: "stopped" | "starting" | "running" | "crashed" | "restarting";
}

// -----------------------------------------------------------------------
// Commitment event (input shape for composition hooks)
// -----------------------------------------------------------------------

/**
 * A commitment event from the chat coordination gate or policy engine
 * commitment boundary. This is the input to the composition adapter.
 */
export interface CommitmentEvent {
  /** Source event ID (from the signed event envelope). */
  event_id: string;
  /** Source event type. */
  event_type: string;
  /** Agent ID that emitted the commitment. */
  agent_id: string;
  /** Counterparty agent ID. */
  counterparty_id: string;
  /** Commitment class. */
  commitment_class: string;
  /** Fortress ID. */
  fortress_id: string;
  /** Emitter node ID. */
  emitter_node: string;
  /** References from mesh quorum (for intra-mesh references graph). */
  mesh_peer_refs?: string[];
  /** Bounded scope from the commitment boundary request. */
  bounded_scope?: {
    deliverable: string;
    deadline_or_terminal: string;
    budget_ref: string;
  };
  /** Signature scheme. */
  signature_scheme: SignatureScheme;
  /** ISO8601 UTC. */
  emitted_at: string;
}

// -----------------------------------------------------------------------
// Composition event payload (for signed-event envelope)
// -----------------------------------------------------------------------

/**
 * Payload for composition_* events emitted through the mesh.
 */
export interface CompositionEventPayload {
  composition_event_type: CompositionEventType;
  source_event_id?: string;
  receipt_id?: string;
  signal_id?: string;
  mandate_id?: string;
  degraded?: boolean;
  reason?: string;
  sidecar_state?: string;
  signature_scheme: SignatureScheme;
  metadata?: Record<string, unknown>;
}
