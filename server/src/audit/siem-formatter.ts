/**
 * Sanctuary MCP Server — SIEM Export Formatters (agent-facing, ALLOWLIST)
 *
 * Formats audit log entries in standard security event formats:
 * - CEF (Common Event Format)
 * - OCSF (Open Cybersecurity Schema Framework)
 *
 * Used by the agent-callable `audit_export_siem` tool to export events to Splunk,
 * Datadog, and other SIEMs.
 *
 * SECURITY (property #11, no-policy-inference; CISO MED-1 2026-06-15): because
 * `audit_export_siem` is an agent-callable Tier-3 tool, these formatters consume
 * ONLY the agent-facing ALLOWLIST view of an entry (timestamp, operation, result,
 * has_details) plus the explicitly-safe `decision` detail value. They do NOT read
 * the raw audit `details`, so the policy `tier`, the matched `rule_id`, the agent
 * DID, the session id, and the threshold-bearing free-text `reason` can never
 * ride out through a SIEM record. Severity is derived from `result`/`decision`
 * only — never from the policy tier.
 *
 * A FULL-FIDELITY operator SIEM export (tier-derived severity, agent DID, session
 * correlation) is a legitimate operator need but belongs behind an operator
 * approval gate; re-tiering `audit_export_siem` to Tier-1 is flagged as a
 * recommendation for the operator (see siem-tools.ts).
 */

import type { AgentAuditView } from "../l2-operational/agent-audit-redaction.js";

// ── Coarse decision (agent-safe) ────────────────────────────────────────

/**
 * The coarse allow/deny outcome the calling agent already knows for its OWN
 * operation. Deliberately 2-valued: the approve-vs-auto-allow distinction is a
 * POLICY TIER signal (did the operation need human approval?), which is exactly
 * what property #11 forbids leaking — so it is collapsed. This is NOT the raw
 * operator gate decision; it is derived from the allowlisted `decision` value
 * (the agent's own observed outcome) and the entry `result`.
 */
export type AgentDecision = "allow" | "deny";

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
 * outcome/result only — never from the (operator-only) policy tier:
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
 * Derived from the outcome only — never from the (operator-only) policy tier.
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
