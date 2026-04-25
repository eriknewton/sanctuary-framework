/**
 * Sanctuary v1.1 — Local Agent Registry Records
 *
 * Shared shape for the per-agent record returned by the operator hub registry
 * API. Implementations of the hub API workstream (Prompt 5) write these;
 * dashboard UI (Prompt 8), internal coordination (Prompt 6), and the exit
 * bundle workstream (Prompt 7) read these.
 *
 * Local-only invariant:
 * Records describe agents wrapped by a single fortress on a single operator's
 * machine. Cross-fortress agent discovery is deferred to v1.3.
 *
 * No-secret invariant:
 * Records MUST NOT carry private keys, passphrases, recovery seeds, or raw
 * provider credentials. Provider identifiers and policy ids are safe;
 * provider tokens are not.
 */

import type {
  HubAgentStatus,
  SignatureScheme,
} from "./constants.js";

/**
 * Coarse harness label. Mirrors the README-supported wrap targets at v1.1
 * ship. Adding a harness requires a new entry here plus harness-compatibility
 * coverage from Prompt 9.
 */
export type LocalHarnessKind =
  | "openclaw"
  | "hermes"
  | "claude_code"
  | "cursor"
  | "cline"
  | "generic_mcp"
  | "other";

/**
 * Provider category for the underlying model. Distinct from the privacy
 * destination category enum because providers and destinations are not 1:1
 * (one provider can serve multiple destination categories).
 */
export interface LocalAgentModelProvider {
  /** Coarse provider label, e.g., "anthropic", "openai", "xai", "local", "other". */
  vendor: string;
  /** Concrete model identifier reported by the provider, e.g., "claude-opus-4". */
  model_id: string;
  /**
   * Whether the model runs locally (on-device or LAN) versus a remote provider.
   * Local models still flow through the privacy filter where applicable.
   */
  runs_locally: boolean;
}

/**
 * Budget summary surfaced to the hub. Concrete budget enforcement lives in
 * the policy engine; this is a read-only snapshot.
 */
export interface LocalAgentBudgetSummary {
  /** Daily bucket. */
  daily?: {
    /** Allotment unit, e.g., "tokens", "usd". */
    unit: string;
    /** Total allotment for the bucket. */
    cap: number;
    /** Amount used so far in the bucket window. */
    used: number;
    /** Soft-warn threshold fraction (0..1). */
    soft_warn?: number;
  };
  /** Monthly bucket. */
  monthly?: {
    unit: string;
    cap: number;
    used: number;
    soft_warn?: number;
  };
  /** ISO8601 timestamp of last budget refresh. */
  last_refreshed_at: string;
}

/**
 * The canonical local agent registry record for v1.1.
 *
 * Implementations SHOULD treat this as read-from-storage; mutating fields is
 * the responsibility of the hub API plus the underlying agent lifecycle owner
 * (wrap / unwrap / template assignment / lockdown).
 */
export interface LocalAgentRecord {
  version: "1.1";
  /** Stable agent identifier, scoped to this fortress. */
  agent_id: string;
  /** Operator identity that owns the agent. */
  identity_id: string;
  /** Harness the agent runs under. */
  harness: LocalHarnessKind;
  /** Free-text harness version string from the harness, when available. */
  harness_version?: string;
  /** Model and provider details. */
  model_provider: LocalAgentModelProvider;
  /** Bound policy id (compiled policy artifact). */
  policy_id: string;
  /**
   * Bound channel-template id, when one applies. Template id space is owned
   * by the policy engine.
   */
  channel_template_id?: string;
  /** Current lifecycle status as surfaced to the hub. */
  status: HubAgentStatus;
  /**
   * Free-text reason for the current status. Templated where status is
   * locked_down or error; absent otherwise.
   */
  status_reason?: string;
  /** Budget summary snapshot. */
  budget_summary: LocalAgentBudgetSummary;
  /** ISO8601 timestamp of last agent activity. */
  last_activity_at: string;
  /** ISO8601 timestamp of wrap. */
  wrapped_at: string;
  /**
   * Capabilities flag set surfaced by the harness. Stable string set;
   * dashboard renders supported controls based on this set.
   */
  capabilities: {
    can_pause: boolean;
    can_resume: boolean;
    can_restart: boolean;
    can_unwrap: boolean;
    can_lockdown: boolean;
    can_chat: boolean;
    can_change_template: boolean;
  };
  /**
   * Signature scheme on any signed audit entries that reference this record.
   * Surfacing the scheme here lets the dashboard show "ed25519-v1" alongside
   * the agent without crawling the audit chain.
   */
  signature_scheme: SignatureScheme;
}

/**
 * Hub-side filter shape used by the registry list API. Workstreams may extend
 * with additional filters; the canonical fields below are stable.
 */
export interface LocalAgentRegistryFilter {
  /** Restrict to one identity id. */
  identity_id?: string;
  /** Restrict to one or more harness kinds. */
  harnesses?: LocalHarnessKind[];
  /** Restrict to one or more lifecycle statuses. */
  statuses?: HubAgentStatus[];
  /**
   * Maximum records to return. Implementations SHOULD enforce a server-side
   * upper bound regardless of caller value.
   */
  limit?: number;
  /** Pagination cursor; opaque to the caller. */
  cursor?: string;
}
