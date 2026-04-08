/**
 * Sanctuary MCP Server — SIEM Export Formatters
 *
 * Formats audit log entries in standard security event formats:
 * - CEF (Common Event Format)
 * - OCSF (Open Cybersecurity Schema Framework)
 *
 * Used by the audit_export_siem tool to export events to Splunk, Datadog, and other SIEMs.
 */

import type { AuditEntry } from "./audit-log.js";

// ── Gate Decision Type ──────────────────────────────────────────────────

export type GateDecision = "approve" | "deny" | "auto-allow";

/**
 * Parse gate decision from audit entry details.
 * Defaults to "auto-allow" if not specified.
 */
function parseGateDecision(details?: Record<string, unknown>): GateDecision {
  if (!details || typeof details.gate_decision !== "string") {
    return "auto-allow";
  }
  const decision = details.gate_decision.toLowerCase();
  if (decision === "approve" || decision === "deny") {
    return decision;
  }
  return "auto-allow";
}

/**
 * Parse tier level from audit entry details (default to 3 if not specified).
 */
function parseTier(details?: Record<string, unknown>): number {
  if (!details || typeof details.tier !== "number") {
    return 3;
  }
  return Math.max(1, Math.min(3, details.tier)); // Clamp to 1-3
}

/**
 * Parse session ID from audit entry details.
 */
function parseSessionId(details?: Record<string, unknown>): string {
  if (!details || typeof details.session_id !== "string") {
    return "unknown";
  }
  return details.session_id;
}

/**
 * Parse agent DID from audit entry details.
 */
function parseAgentDid(details?: Record<string, unknown>): string {
  if (!details || typeof details.agent_did !== "string") {
    return "unknown";
  }
  return details.agent_did;
}

// ── CEF (Common Event Format) Formatter ─────────────────────────────────

export interface CEFOptions {
  /**
   * CEF version (default: "0")
   */
  version?: string;

  /**
   * Vendor name (default: "Sanctuary")
   */
  vendor?: string;

  /**
   * Product name (default: "MCP-Server")
   */
  product?: string;

  /**
   * Product version (default: "0.7.0")
   */
  productVersion?: string;
}

/**
 * Map gate decision and tier to CEF severity (0-10).
 * - deny = 8 (high severity)
 * - approve(T1) = 5 (medium)
 * - approve(T2) = 3 (low)
 * - auto-allow(T3) = 1 (informational)
 */
function gateToCEFSeverity(decision: GateDecision, tier: number): number {
  if (decision === "deny") {
    return 8;
  }
  if (decision === "approve") {
    if (tier === 1) return 5; // Tier 1 requires manual approval
    if (tier === 2) return 3; // Tier 2 requires careful review
  }
  return 1; // auto-allow or tier 3
}

/**
 * Format an audit entry as CEF (Common Event Format).
 *
 * Produces a single-line CEF event suitable for Splunk, QRadar, etc.
 *
 * Format:
 * ```
 * CEF:0|Sanctuary|MCP-Server|0.7.0|<tool_name>|<description>|<severity>|src=<agent_did> act=<tool_name> outcome=<gate_decision> tier=<tier> cs1=<session_id> cs1Label=SessionId
 * ```
 */
export function formatAsCEF(entry: AuditEntry, options?: CEFOptions): string {
  const version = options?.version ?? "0";
  const vendor = options?.vendor ?? "Sanctuary";
  const product = options?.product ?? "MCP-Server";
  const productVersion = options?.productVersion ?? "0.7.0";

  const decision = parseGateDecision(entry.details);
  const tier = parseTier(entry.details);
  const sessionId = parseSessionId(entry.details);
  const agentDid = parseAgentDid(entry.details);

  const severity = gateToCEFSeverity(decision, tier);
  const signatureId = entry.operation.replace(/[^a-zA-Z0-9_-]/g, "_");
  const description = `Sanctuary ${entry.operation}`;

  // Build extension (key=value pairs)
  const extensions = [
    `src=${agentDid}`,
    `act=${entry.operation}`,
    `outcome=${decision}`,
    `tier=${tier}`,
    `cs1=${sessionId}`,
    `cs1Label=SessionId`,
    `rt=${new Date(entry.timestamp).getTime()}`,
    `layer=${entry.layer}`,
    `result=${entry.result}`,
  ];

  return `CEF:${version}|${vendor}|${product}|${productVersion}|${signatureId}|${description}|${severity}|${extensions.join(" ")}`;
}

// ── OCSF (Open Cybersecurity Schema Framework) Formatter ────────────────

/**
 * Map gate decision to OCSF status_id (1=success, 2=failure).
 */
function gateToOCSFStatus(decision: GateDecision, result: "success" | "failure"): 1 | 2 {
  return decision === "deny" || result === "failure" ? 2 : 1;
}

/**
 * Map gate decision and tier to OCSF severity_id (1=Informational, 4=Critical).
 */
function gateToCOCSFSeverity(decision: GateDecision, tier: number): 1 | 2 | 3 | 4 {
  if (decision === "deny") {
    return 4; // Critical
  }
  if (decision === "approve") {
    if (tier === 1) return 3; // High
    if (tier === 2) return 2; // Medium
  }
  return 1; // Informational (auto-allow or tier 3)
}

/**
 * Map gate decision to OCSF disposition_id (1=allowed, 2=blocked).
 */
function gateToOCSFDisposition(decision: GateDecision): 1 | 2 {
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
 * Format an audit entry as OCSF (Open Cybersecurity Schema Framework).
 *
 * Returns a JSON object conforming to OCSF class_uid 3001 (API Activity).
 *
 * OCSF is a vendor-agnostic schema used by Splunk, Datadog, CrowdStrike, and others.
 */
export function formatAsOCSF(entry: AuditEntry): OCSFObject {
  const decision = parseGateDecision(entry.details);
  const tier = parseTier(entry.details);
  const sessionId = parseSessionId(entry.details);
  const agentDid = parseAgentDid(entry.details);

  const timestamp = new Date(entry.timestamp).getTime();
  const statusId = gateToOCSFStatus(decision, entry.result);
  const severityId = gateToCOCSFSeverity(decision, tier);
  const dispositionId = gateToOCSFDisposition(decision);

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
        uid: agentDid,
      },
    },
    api: {
      operation: entry.operation,
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
