/**
 * Sanctuary v1.3 WP-V1.3-1 Sentinel Baseline Pack (Castle Layer 2 anchor)
 *
 * Shared types for the Sentinel observation surface.
 *
 * Castle-walking discipline:
 *  - Castle Layer 1 (Castle Wall) blocks unauthorized egress at the kernel
 *    boundary. That is the enforcement layer.
 *  - Castle Layer 2 (Sentinels) observes server-local data only and surfaces
 *    anomalies. NO outbound network. NO blocking. Findings flow into the
 *    operator surface they already check.
 *  - Castle Layer 3 (Cooperative MCP) is the agent contract. Sentinels do
 *    not wrap agent tools and do not negotiate with agents.
 *
 * Phi-1 ships the framework + the egress-volume watcher. Phi-2 through
 * Phi-5 add credential-usage, cross-agent-chatter, suspicious-tool-call,
 * and anomaly-trigger sentinels against this same shape.
 */

import type { AuditLog, AuditEntry } from "../operational/audit-log.js";
import type { SubstrateSelector } from "../intelligence/selector.js";
import type { SentinelFindingStore } from "./sentinel-finding-store.js";

/** Severity tier returned by `Sentinel.evaluate()`. */
export type SentinelSeverity = "info" | "warn" | "alert";

/**
 * Read-only context handed to every sentinel on subscribe + evaluate.
 * Sentinels do NOT receive a writable storage handle and do NOT receive
 * an outbound HTTP client. The substrate selector is the single
 * outbound-capable surface; Phi-1 sentinels do not exercise it but
 * Phi-2/3/4/5 may want to invoke a local LLM for reasoning.
 */
export interface SentinelContext {
  /** Stable per-fortress identifier; multi-fortress isolation pivot. */
  fortressId: string;
  /** Audit log read API. Sentinels MUST NOT call append() through this. */
  auditLog: AuditLog;
  /** Optional substrate selector for LLM-backed reasoning. v1.3 Phi-1 unused. */
  substrateSelector?: SubstrateSelector;
  /** Wall-clock provider. Tests inject a deterministic clock. */
  now: () => Date;
  /**
   * Optional read view of the per-fortress sentinel finding store
   * (Phi-1 surface). First-order sentinels (Phi-1/2/3/4) do not need
   * this; the Phi-5 meta-sentinel reads it to detect patterns ACROSS
   * other sentinels' findings (compound finding, fortress-wide count
   * spikes, novel sentinel-ID combinations). The dispatcher attaches
   * the store automatically on `subscribeSentinel`; tests can omit it
   * when constructing a context literal for a first-order watcher.
   *
   * Multi-fortress isolation rides on the store's existing key shape:
   * the store is constructed per-fortress from the fortress master
   * key, so two fortresses' stores produce distinct ciphertext for
   * identical finding-ids and one fortress's read cannot decode
   * another fortress's findings.
   */
  findingStore?: SentinelFindingStore;
}

/**
 * One observation a sentinel produced. Persisted under the sentinel
 * findings store + emitted as an audit event +
 * surfaced to the operator dashboard.
 */
export interface SentinelFinding {
  /** Stable per-fortress finding id (UUID v4). */
  finding_id: string;
  /** Identifier of the sentinel that produced this finding. */
  sentinel_id: string;
  severity: SentinelSeverity;
  /**
   * Optional agent-id this finding pertains to. Absent when the finding
   * is fortress-wide (e.g. cross-agent chatter spike).
   */
  agent_id?: string;
  /** Operator-friendly one-liner. Truncated to 240 chars on persist. */
  summary: string;
  /**
   * Structured payload. Schema varies per sentinel but every payload is
   * a flat record of JSON-serializable values.
   */
  details: Record<string, unknown>;
  /** ISO 8601 timestamp at evaluation time. */
  observed_at: string;
  /**
   * Audit-log entries that triggered this finding. Sentinels populate
   * with `${entry.timestamp}:${entry.operation}` tuples (mirrors the
   * aggregator's audit_log_entry_id shape from Upsilon-1).
   */
  evidence_audit_ids: string[];
  /** Stable fortress id stamped at emit. Multi-fortress isolation pivot. */
  fortress_id: string;
}

/** Hard cap for the operator-friendly summary field. */
export const SENTINEL_SUMMARY_MAX_CHARS = 240;

/**
 * Audit-log operation names emitted by the sentinel framework. Adding
 * a new event here is a forward-compatible change; v0.1 mesh receivers
 * silently drop these because they are inside the
 * `cross_harness_approval_` / `sentinel_*` reserved namespace cousins.
 */
export const SENTINEL_AUDIT_OPS = {
  SUBSCRIBED: "sentinel_subscribed",
  UNSUBSCRIBED: "sentinel_unsubscribed",
  FINDING_EMITTED: "sentinel_finding_emitted",
  EVALUATION_FAILED: "sentinel_evaluation_failed",
} as const;

export type SentinelAuditOp =
  (typeof SENTINEL_AUDIT_OPS)[keyof typeof SENTINEL_AUDIT_OPS];

/**
 * Audit operations the framework READS to power its baseline +
 * anomaly detection. Sentinels filter audit-log entries by these
 * prefixes; centralizing the names avoids drift between watcher
 * implementations.
 */
export const SENTINEL_OBSERVED_AUDIT_OPS = {
  /** Proxy router emits this on every outbound call (success or failure). */
  PROXY_CALL_PREFIX: "proxy_call:",
} as const;

/** Helper: filter `proxy_call:*` audit entries. */
export function isProxyCallAuditEntry(entry: AuditEntry): boolean {
  return entry.operation.startsWith(
    SENTINEL_OBSERVED_AUDIT_OPS.PROXY_CALL_PREFIX,
  );
}

/** Helper: extract the upstream server name from a proxy_call entry. */
export function proxyServerFromAuditEntry(entry: AuditEntry): string | null {
  if (!isProxyCallAuditEntry(entry)) return null;
  const details = entry.details as Record<string, unknown> | undefined;
  if (!details) return null;
  const server = details["server"];
  if (typeof server !== "string" || server.length === 0) return null;
  return server;
}
