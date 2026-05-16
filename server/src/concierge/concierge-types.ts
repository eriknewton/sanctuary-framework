import type { AuditEntry } from "../l2-operational/audit-log.js";
import type { PublicIdentity } from "../core/identity.js";
import type { HubInboxItem } from "../contracts/v1.1/hub-events.js";
import type { Task, TaskStatus } from "../l2-operational/task-coordination/index.js";

export const CONCIERGE_PROMPT_DOMAIN = "sanctuary.concierge.v1\n";

export const CONCIERGE_READ_SURFACES = [
  "audit_log",
  "identity_registry",
  "approval_inbox",
  "sovereignty_profile",
  "task_state",
  "state_store",
] as const;

export type ConciergeReadSurface = (typeof CONCIERGE_READ_SURFACES)[number];

export interface ConciergeAskRequest {
  question: string;
  stream?: boolean;
  includePayloads?: boolean;
  maxAuditEntries?: number;
  now?: Date;
}

export interface ConciergeAskResponse {
  answer: string;
  model: string;
  provider: "venice";
  read_surfaces: ConciergeReadSurface[];
  context: ConciergeContextBundle;
}

export interface ConciergeStatus {
  provider: "venice";
  configured: boolean;
  reachable: boolean;
  model: string;
  read_surfaces: ConciergeReadSurface[];
  fallback: "none";
  message: string;
}

export interface ConciergeContextBundle {
  generated_at: string;
  read_surfaces: ConciergeReadSurface[];
  audit_log: AuditLogContext;
  identity_registry: IdentityRegistryContext;
  approval_inbox: ApprovalInboxContext;
  sovereignty_profile: SovereigntyProfileContext;
  task_state: TaskStateContext;
  state_store: StateStoreContext;
}

export interface AuditLogContext {
  total_matching: number;
  entries: AuditEntry[];
  integrity_findings: unknown[];
}

export interface IdentityRegistryContext {
  identities: Array<
    PublicIdentity & {
      kid: string;
      roles: string[];
      rotation_count?: number;
    }
  >;
}

export interface ApprovalInboxContext {
  pending_count: number;
  items: Array<
    Pick<HubInboxItem, "item_id" | "kind" | "created_at" | "resolved"> & {
      age_seconds: number;
      status: "pending" | "resolved";
      tier?: string;
      operation_category?: string;
      agent_id?: string;
      identity_id?: string;
    }
  >;
}

export interface SovereigntyProfileContext {
  fortress_id: string;
  storage_path?: string;
  tier_policy: string;
  context_gating_state: string;
  castle_wall: {
    dashboard_enabled: boolean;
    dashboard_host?: string;
    dashboard_port?: number;
    transport?: string;
  };
}

export interface TaskStateContext {
  total: number;
  status_counts: Record<TaskStatus, number>;
  tasks: Task[];
  recent_activity: Array<{
    task_id: string;
    title: string;
    status: TaskStatus;
    updated_at: string;
    assignee?: string;
  }>;
}

export interface StateStoreContext {
  include_payloads: boolean;
  namespaces: Array<{
    namespace: string;
    total_keys: number;
    recent_keys: Array<{
      key: string;
      version: number;
      size_bytes: number;
      written_at: string;
      tags: string[];
      payload?: string;
    }>;
  }>;
}

export interface VeniceMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface VeniceCompleteRequest {
  messages: VeniceMessage[];
  model?: string;
  stream?: boolean;
  onToken?: (token: string) => void;
}

export interface VeniceClientLike {
  complete(request: VeniceCompleteRequest): Promise<string>;
  checkStatus(): Promise<ConciergeStatus>;
  model(): string;
}

export class ConciergeUnavailableError extends Error {
  readonly code = "CONCIERGE_UNAVAILABLE";
  override readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "ConciergeUnavailableError";
    this.cause = cause;
  }
}

export class ConciergeReadError extends Error {
  readonly code = "CONCIERGE_READ_FAILED";
  override readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "ConciergeReadError";
    this.cause = cause;
  }
}
