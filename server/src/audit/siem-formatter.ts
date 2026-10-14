/**
 * Sanctuary MCP Server - SIEM Export Formatters (agent-facing, ALLOWLIST)
 *
 * Formats audit log entries in standard security event formats:
 * - CEF (Common Event Format)
 * - OCSF (Open Cybersecurity Schema Framework)
 * - ECS (Elastic Common Schema)
 * - XDM (Cortex Data Model)
 *
 * Used by the Tier 1 `audit_export_siem` tool to export events for SIEM ingestion.
 *
 * SECURITY (property #11, no-policy-inference; CISO MED-1 2026-06-15): because
 * `audit_export_siem` is a Tier 1 export tool, these formatters consume
 * ONLY the agent-facing ALLOWLIST view of an entry (timestamp, operation, result,
 * has_details). They do NOT read the raw audit `details`, so the policy `tier`,
 * the matched `rule_id`, the agent DID, the session id, and the
 * threshold-bearing free-text `reason` can never ride out through a SIEM record.
 * Severity is derived from `result` only - never from the policy tier.
 *
 * A FULL-FIDELITY operator SIEM export (tier-derived severity, agent DID, session
 * correlation) is a legitimate operator need but belongs behind an operator
 * approval gate; `audit_export_siem` is Tier 1 for that reason (see
 * siem-tools.ts).
 *
 * ECS mapping table (source -> exported field):
 * - constant -> ecs.version
 * - view.timestamp -> @timestamp
 * - constant -> event.kind
 * - constant -> event.category
 * - constant -> event.type
 * - constant -> event.module
 * - constant -> event.dataset
 * - constant -> event.provider
 * - view.operation -> event.action
 * - view.result -> event.outcome
 * - agentDecision(view) -> event.severity
 * - constant -> service.name
 * - constant -> service.type
 * - constant -> user.id
 * - agentDecision(view) -> sanctuary.audit.decision
 * - view.result -> sanctuary.audit.result
 *
 * XDM mapping table (source -> exported field):
 * - view.timestamp -> sanctuary_time
 * - constant -> sanctuary_event_type
 * - view.operation -> sanctuary_event_description
 * - view.operation -> sanctuary_event_operation
 * - agentDecision(view) -> sanctuary_event_operation_sub_type
 * - view.result -> sanctuary_event_outcome
 * - constant -> sanctuary_event_is_completed
 * - constant -> sanctuary_observer_product
 * - constant -> sanctuary_observer_vendor
 * - constant -> sanctuary_source_user_username
 * - agentDecision(view) -> sanctuary_audit_decision
 * - view.result -> sanctuary_audit_result
 */

import type { AgentAuditView } from "../operational/agent-audit-redaction.js";

// ── Coarse decision (agent-safe) ────────────────────────────────────────

/**
 * The coarse allow/deny outcome the calling agent already knows for its OWN
 * operation. Deliberately 2-valued: the approve-vs-auto-allow distinction is a
 * POLICY TIER signal (did the operation need human approval?), which is exactly
 * what property #11 forbids leaking, so it is collapsed. This is NOT the raw
 * operator gate decision; it is derived from the allowlisted `decision` value
 * (the agent's own observed outcome) and the entry `result`.
 */
export type AgentDecision = "allow" | "deny";

export const SIEM_ECS_FIELD_MAPPING = {
  ecsVersion: "ecs.version",
  timestamp: "@timestamp",
  eventKind: "event.kind",
  eventCategory: "event.category",
  eventType: "event.type",
  eventModule: "event.module",
  eventDataset: "event.dataset",
  eventProvider: "event.provider",
  eventAction: "event.action",
  eventOutcome: "event.outcome",
  eventSeverity: "event.severity",
  serviceName: "service.name",
  serviceType: "service.type",
  userId: "user.id",
  sanctuaryDecision: "sanctuary.audit.decision",
  sanctuaryResult: "sanctuary.audit.result",
} as const;

export const SIEM_XDM_FIELD_MAPPING = {
  timestamp: "sanctuary_time",
  eventType: "sanctuary_event_type",
  eventDescription: "sanctuary_event_description",
  eventOperation: "sanctuary_event_operation",
  eventOperationSubType: "sanctuary_event_operation_sub_type",
  eventOutcome: "sanctuary_event_outcome",
  eventIsCompleted: "sanctuary_event_is_completed",
  observerProduct: "sanctuary_observer_product",
  observerVendor: "sanctuary_observer_vendor",
  sourceUserUsername: "sanctuary_source_user_username",
  sanctuaryDecision: "sanctuary_audit_decision",
  sanctuaryResult: "sanctuary_audit_result",
} as const;

/**
 * Normalize the agent-safe coarse outcome from the allowlisted `decision` value
 * (if present) and the entry `result`. A `failure` result, or an allowlisted
 * `decision` beginning with "deny"/"drop"/"block", maps to "deny"; everything
 * else (including an explicit "allow"/"approve"/"auto-allow") maps to "allow".
 */
export function agentDecision(
  view: AgentAuditView,
  safeDecision?: string
): AgentDecision {
  if (typeof safeDecision === "string") {
    const d = safeDecision.toLowerCase();
    if (d.startsWith("deny") || d.startsWith("drop") || d.startsWith("block")) {
      return "deny";
    }
    if (d.startsWith("allow") || d.startsWith("approve") || d.startsWith("auto")) {
      return "allow";
    }
  }
  return view.result === "failure" ? "deny" : "allow";
}

// ── CEF (Common Event Format) Formatter ─────────────────────────────────

export interface CEFOptions {
  /** CEF version (default: "0") */
  version?: string;
  /** Vendor name (default: "Sanctuary") */
  vendor?: string;
  /** Product name (default: "MCP-Server") */
  product?: string;
  /** Product version (default: "0.7.0") */
  productVersion?: string;
}

/**
 * Map the agent-safe outcome to CEF severity (0-10). Severity is derived from the
 * outcome/result only, never from the (operator-only) policy tier:
 * - deny / failure = 8 (high)
 * - allow / auto-allow = 1 (informational)
 */
function agentToCEFSeverity(decision: AgentDecision): number {
  return decision === "deny" ? 8 : 1;
}

/**
 * Format an agent-facing audit view as CEF (Common Event Format).
 *
 * Produces a single-line CEF event suitable for Splunk, QRadar, etc., built ONLY
 * from allowlisted fields. There is no `src` (agent DID), no `tier`, and no
 * session id, so no operator/policy attribution leaks.
 */
export function formatAsCEF(
  view: AgentAuditView,
  safeDecision?: string,
  options?: CEFOptions
): string {
  const version = options?.version ?? "0";
  const vendor = options?.vendor ?? "Sanctuary";
  const product = options?.product ?? "MCP-Server";
  const productVersion = options?.productVersion ?? "0.7.0";

  const decision = agentDecision(view, safeDecision);
  const severity = agentToCEFSeverity(decision);
  const signatureId = view.operation.replace(/[^a-zA-Z0-9_-]/g, "_");
  const description = `Sanctuary ${view.operation}`;

  // Extension (key=value pairs). Allowlisted fields only.
  const extensions = [
    `act=${view.operation}`,
    `outcome=${decision}`,
    `rt=${new Date(view.timestamp).getTime()}`,
    `result=${view.result}`,
  ];

  return `CEF:${version}|${vendor}|${product}|${productVersion}|${signatureId}|${description}|${severity}|${extensions.join(" ")}`;
}

// ── OCSF (Open Cybersecurity Schema Framework) Formatter ────────────────

/**
 * Map the agent-safe outcome + result to OCSF status_id (1=success, 2=failure).
 */
function agentToOCSFStatus(view: AgentAuditView, decision: AgentDecision): 1 | 2 {
  return decision === "deny" || view.result === "failure" ? 2 : 1;
}

/**
 * Map the agent-safe outcome to OCSF severity_id (1=Informational, 4=Critical).
 * Derived from the outcome only, never from the (operator-only) policy tier.
 */
function agentToOCSFSeverity(decision: AgentDecision): 1 | 4 {
  return decision === "deny" ? 4 : 1;
}

/**
 * Map the agent-safe outcome to OCSF disposition_id (1=allowed, 2=blocked).
 */
function agentToOCSFDisposition(decision: AgentDecision): 1 | 2 {
  return decision === "deny" ? 2 : 1;
}

export interface OCSFObject {
  class_uid: number;
  class_name: string;
  category_uid: number;
  category_name: string;
  severity_id: 1 | 2 | 3 | 4;
  time: number;
  activity_id: number;
  activity_name: string;
  actor: { user: { uid: string } };
  api: { operation: string; service: { name: string } };
  status_id: 1 | 2;
  disposition_id: 1 | 2;
  metadata: {
    version: string;
    product: { name: string; vendor_name: string; version: string };
  };
}

/**
 * Format an agent-facing audit view as OCSF (Open Cybersecurity Schema Framework).
 *
 * Returns a JSON object conforming to OCSF class_uid 3001 (API Activity), built
 * ONLY from allowlisted fields. The actor uid is a fixed "self" sentinel (the
 * export is already scoped to the caller's own identity) rather than the raw
 * agent DID, so no identity or policy attribution leaks.
 */
export function formatAsOCSF(view: AgentAuditView, safeDecision?: string): OCSFObject {
  const decision = agentDecision(view, safeDecision);
  const timestamp = new Date(view.timestamp).getTime();
  const statusId = agentToOCSFStatus(view, decision);
  const severityId = agentToOCSFSeverity(decision);
  const dispositionId = agentToOCSFDisposition(decision);

  return {
    class_uid: 3001,
    class_name: "API Activity",
    category_uid: 3,
    category_name: "Application Activity",
    severity_id: severityId,
    time: timestamp,
    activity_id: 1,
    activity_name: "API Call",
    actor: {
      user: {
        // Scoped to the caller's own identity already; emit a fixed self
        // sentinel rather than the raw DID (no identity leak).
        uid: "self",
      },
    },
    api: {
      operation: view.operation,
      service: {
        name: "sanctuary-mcp",
      },
    },
    status_id: statusId,
    disposition_id: dispositionId,
    metadata: {
      version: "1.3.0",
      product: {
        name: "Sanctuary Framework",
        vendor_name: "Erik Newton",
        version: "0.7.0",
      },
    },
  };
}

// ── ECS (Elastic Common Schema) Formatter ───────────────────────────────

export interface ECSObject {
  "@timestamp": string | null;
  ecs: { version: string };
  event: {
    kind: "event";
    category: ["configuration"];
    type: ["info"];
    module: "sanctuary";
    dataset: "sanctuary.audit";
    provider: "sanctuary-mcp";
    action: string;
    outcome: "success" | "failure";
    severity: 1 | 8;
  };
  service: { name: "sanctuary-mcp"; type: "mcp" };
  user: { id: "self" };
  sanctuary: {
    audit: {
      decision: AgentDecision;
      result: "success" | "failure";
    };
  };
}

function agentToECSSeverity(decision: AgentDecision): 1 | 8 {
  return decision === "deny" ? 8 : 1;
}

/**
 * Format an agent-facing audit view as ECS (Elastic Common Schema).
 *
 * The object uses standard ECS fields where a direct home exists; Sanctuary's
 * coarse allow/deny projection is duplicated under `sanctuary.audit.decision`
 * because ECS has no exact field for the collapsed gate decision. The formatter
 * consumes only the redacted agent view and never raw audit details.
 */
export function formatAsECS(view: AgentAuditView): ECSObject {
  const decision = agentDecision(view);
  const timestampMs = new Date(view.timestamp).getTime();

  return {
    "@timestamp": Number.isFinite(timestampMs)
      ? new Date(timestampMs).toISOString()
      : null,
    ecs: {
      version: "8.11.0",
    },
    event: {
      kind: "event",
      category: ["configuration"],
      type: ["info"],
      module: "sanctuary",
      dataset: "sanctuary.audit",
      provider: "sanctuary-mcp",
      action: view.operation,
      outcome: view.result,
      severity: agentToECSSeverity(decision),
    },
    service: {
      name: "sanctuary-mcp",
      type: "mcp",
    },
    user: {
      // The export is already scoped to the caller's own identity; a fixed
      // sentinel keeps the raw agent DID out of the SIEM record.
      id: "self",
    },
    sanctuary: {
      audit: {
        decision,
        result: view.result,
      },
    },
  };
}

// ── XDM (Cortex Data Model) Formatter ───────────────────────────────────

export interface XDMObject {
  sanctuary_time: number | null;
  sanctuary_event_type: "application";
  sanctuary_event_description: string;
  sanctuary_event_operation: string;
  sanctuary_event_operation_sub_type: AgentDecision;
  sanctuary_event_outcome: "success" | "failure";
  sanctuary_event_is_completed: true;
  sanctuary_observer_product: "Sanctuary Framework";
  sanctuary_observer_vendor: "Erik Newton";
  sanctuary_source_user_username: "self";
  sanctuary_audit_decision: AgentDecision;
  sanctuary_audit_result: "success" | "failure";
}

/**
 * Format an agent-facing audit view as Cortex raw-event JSON for XDM modeling.
 *
 * Raw keys deliberately avoid the `xdm.*` namespace; Cortex data model rules map
 * these fields into modeled XDM fields, including `xdm.source.user.username`.
 */
export function formatAsXDM(view: AgentAuditView): XDMObject {
  const decision = agentDecision(view);
  const timestampMs = new Date(view.timestamp).getTime();

  return {
    sanctuary_time: Number.isFinite(timestampMs) ? timestampMs : null,
    sanctuary_event_type: "application",
    sanctuary_event_description: `Sanctuary ${view.operation}`,
    sanctuary_event_operation: view.operation,
    sanctuary_event_operation_sub_type: decision,
    sanctuary_event_outcome: view.result,
    sanctuary_event_is_completed: true,
    sanctuary_observer_product: "Sanctuary Framework",
    sanctuary_observer_vendor: "Erik Newton",
    sanctuary_source_user_username: "self",
    sanctuary_audit_decision: decision,
    sanctuary_audit_result: view.result,
  };
}
