/**
 * Tool outcome classification for the MCP router's refusal boundary.
 *
 * The router asks one question of every result a registered tool's handler
 * returns: is this that tool's own success shape, or a refusal? Success passes
 * through unchanged; every refusal leaves the boundary as one fixed result.
 * This module answers the question from the result alone (taken as untyped
 * data, because a handler may add fields such as `isError` by spread) and,
 * for proxied upstream tools, from an origin fact the proxy recorded on the
 * exact object it returned. It never imports `router.ts`, so the router can
 * import it without an import cycle.
 */

import { isNamespaceDiscoveryLimitError } from "./storage/interface.js";
import type { DenialCause } from "./agent-native/denial-ledger.js";

export type ToolOutcome = "success" | "refusal";

/**
 * What the proxy knows about one result it returned, recorded beside the
 * object rather than inside it so no byte of the delivered result changes.
 */
export interface ProxiedOutcomeFact {
  /** The upstream result carried `isError: true`, or the upstream call failed. */
  readonly upstream_failed: boolean;
  /** The proxy itself refused the call before or instead of forwarding it. */
  readonly proxy_refusal: boolean;
}

// Proxied tools are known by object identity, never by name: an ordinary tool
// can be named `proxy/x/y`, and only a definition the proxy built is marked.
const proxiedToolDefinitions = new WeakSet<object>();
const proxiedOutcomeFacts = new WeakMap<object, ProxiedOutcomeFact>();

/** Mark a tool definition the proxy built; must be called on the object registered. */
export function markProxiedTool<T extends object>(definition: T): T {
  proxiedToolDefinitions.add(definition);
  return definition;
}

export function isProxiedTool(definition: unknown): boolean {
  return typeof definition === "object" && definition !== null && proxiedToolDefinitions.has(definition);
}

/** Record the proxy's origin fact on the exact result object it returns. */
export function recordProxiedOutcome<T extends object>(result: T, fact: ProxiedOutcomeFact): T {
  proxiedOutcomeFacts.set(result, Object.freeze({ upstream_failed: fact.upstream_failed, proxy_refusal: fact.proxy_refusal }));
  return result;
}

export function proxiedOutcomeFact(result: unknown): ProxiedOutcomeFact | undefined {
  return typeof result === "object" && result !== null ? proxiedOutcomeFacts.get(result) : undefined;
}

/** The text of every content item, or undefined when the result is an error or not all-text. */
function textItems(result: unknown): string[] | undefined {
  if (typeof result !== "object" || result === null) return undefined;
  const record = result as { isError?: unknown; content?: unknown };
  if (record.isError === true) return undefined;
  if (!Array.isArray(record.content)) return undefined;
  const texts: string[] = [];
  for (const item of record.content as unknown[]) {
    if (typeof item !== "object" || item === null) return undefined;
    const { type, text } = item as { type?: unknown; text?: unknown };
    if (type !== "text" || typeof text !== "string") return undefined;
    texts.push(text);
  }
  return texts;
}

/** A JSON object body that carries no error, denial or partial-failure verdict. */
function isSuccessBody(text: string): boolean {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return false;
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) return false;
  const record = body as Record<string, unknown>;
  return !Object.hasOwn(record, "error")
    && record.denied !== true
    && record.status !== "partial_failed";
}

/** The strict rule: one text item whose text is a JSON object with no verdict. */
function standardOutcome(result: unknown): boolean {
  const texts = textItems(result);
  return texts !== undefined && texts.length === 1 && isSuccessBody(texts[0]!);
}

/**
 * Custom success shapes. Each one only widens the item layout the strict rule
 * accepts, and still rejects a verdict-bearing JSON body: a predicate may
 * accept only an answer the tool computed without any policy or ownership
 * decision after the gate.
 */
const OUTCOME_PREDICATES = {
  // Two text items: a JSON summary object, then the export body (CEF lines or a JSON array) unparsed.
  siem_export: (result: unknown): boolean => {
    const texts = textItems(result);
    return texts !== undefined && texts.length === 2 && isSuccessBody(texts[0]!);
  },
  // Two text items: a plain-text report, then the JSON analysis object it was rendered from.
  sovereignty_report: (result: unknown): boolean => {
    const texts = textItems(result);
    return texts !== undefined && texts.length === 2 && isSuccessBody(texts[1]!);
  },
} as const;

export type ToolOutcomeShape = "standard" | keyof typeof OUTCOME_PREDICATES;

export const TOOL_OUTCOME_PREDICATE_NAMES = Object.freeze(
  Object.keys(OUTCOME_PREDICATES) as Array<keyof typeof OUTCOME_PREDICATES>,
);

/**
 * The success shape of every registered non-proxied tool. Must match the tool
 * set `createSanctuaryServer` registers in `index.ts`, which refuses to start
 * when a registered tool has no entry here (`assertToolOutcomesRegistered`).
 */
export const TOOL_OUTCOME_SHAPES: Readonly<Record<string, ToolOutcomeShape>> = Object.freeze({
  "audit_export_siem": "siem_export",
  "bootstrap_create_escrow": "standard",
  "bootstrap_provide_guarantee": "standard",
  "bridge_attest": "standard",
  "bridge_commit": "standard",
  "bridge_verify": "standard",
  "compliance_eu_ai_act_annex_iii_classify": "standard",
  "compliance_generate_eu_ai_act_bundle": "standard",
  "context_gate_apply_template": "standard",
  "context_gate_enforcer_configure": "standard",
  "context_gate_enforcer_status": "standard",
  "context_gate_filter": "standard",
  "context_gate_list_policies": "standard",
  "context_gate_recommend": "standard",
  "context_gate_set_policy": "standard",
  "disclosure_evaluate": "standard",
  "disclosure_set_policy": "standard",
  "exec_attest": "standard",
  "federation_peers": "standard",
  "federation_status": "standard",
  "federation_trust_evaluate": "standard",
  "governor_reset": "standard",
  "governor_status": "standard",
  "handshake_abort": "standard",
  "handshake_complete": "standard",
  "handshake_exchange": "standard",
  "handshake_initiate": "standard",
  "handshake_respond": "standard",
  "handshake_status": "standard",
  "handshake_verify_attestation": "standard",
  "identity_create": "standard",
  "identity_import": "standard",
  "identity_list": "standard",
  "identity_rotate": "standard",
  "identity_set_primary": "standard",
  "identity_sign": "standard",
  "identity_verify": "standard",
  "l2_hardening_status": "standard",
  "l2_verify_isolation": "standard",
  "manifest": "standard",
  "memory_attest": "standard",
  "memory_count": "standard",
  "memory_delete": "standard",
  "memory_emit": "standard",
  "memory_get": "standard",
  "memory_ingest": "standard",
  "memory_insert": "standard",
  "memory_list": "standard",
  "memory_provenance_clear_bad_signer": "standard",
  "memory_provenance_mark_bad_signer": "standard",
  "memory_provenance_prune_signers": "standard",
  "memory_search": "standard",
  "memory_transcode": "standard",
  "memory_transcode_restore": "standard",
  "monitor_audit_log": "standard",
  "monitor_health": "standard",
  "principal_baseline_view": "standard",
  "principal_policy_view": "standard",
  "proof_commitment": "standard",
  "proof_reveal": "standard",
  "reputation_export": "standard",
  "reputation_import": "standard",
  "reputation_publish": "standard",
  "reputation_query": "standard",
  "reputation_query_weighted": "standard",
  "reputation_record": "standard",
  "sanctuary/resolve_erc8004_identity": "standard",
  "sanctuary/sign_erc8004_identity": "standard",
  "sanctuary_active_protections": "standard",
  "sanctuary_audit_search": "standard",
  "sanctuary_bootstrap": "standard",
  "sanctuary_capabilities": "standard",
  "sanctuary_compound_execute": "standard",
  "sanctuary_distress": "standard",
  "sanctuary_events_close": "standard",
  "sanctuary_events_open_cursor": "standard",
  "sanctuary_events_read": "standard",
  "sanctuary_export_identity_bundle": "standard",
  "sanctuary_forget": "standard",
  "sanctuary_help": "standard",
  "sanctuary_hide": "standard",
  "sanctuary_link_to_human": "standard",
  "sanctuary_policy_status": "standard",
  "sanctuary_recall": "standard",
  "sanctuary_remember": "standard",
  "sanctuary_sign_challenge": "standard",
  "sanctuary_who_am_i": "standard",
  "sdw_export": "standard",
  "sdw_import": "standard",
  "sdw_memory_provenance": "standard",
  "sdw_memory_provenance_abort_migration": "standard",
  "sdw_memory_provenance_migrate": "standard",
  "sdw_memory_provenance_migration_status": "standard",
  "sdw_memory_provenance_repair_completion_marker": "standard",
  "shr_gateway_export": "standard",
  "shr_generate": "standard",
  "shr_verify": "standard",
  "sovereignty_audit": "sovereignty_report",
  "sovereignty_profile_generate_prompt": "standard",
  "sovereignty_profile_get": "standard",
  "sovereignty_profile_update": "standard",
  "state_delete": "standard",
  "state_disclose_unattributed": "standard",
  "state_export": "standard",
  "state_import": "standard",
  "state_list": "standard",
  "state_read": "standard",
  "state_write": "standard",
  "zk_commit": "standard",
  "zk_prove": "standard",
  "zk_range_prove": "standard",
  "zk_range_verify": "standard",
  "zk_verify": "standard",
});

/**
 * Throw when any tool is neither a marked proxied tool nor a registry entry.
 * The error names the tools for the operator; it is raised at startup, never
 * on an agent call.
 */
export function assertToolOutcomesRegistered(
  tools: readonly { readonly name: string }[],
  shapes: Readonly<Record<string, ToolOutcomeShape>> = TOOL_OUTCOME_SHAPES,
): void {
  const missing = tools
    .filter((tool) => !isProxiedTool(tool) && !Object.hasOwn(shapes, tool.name))
    .map((tool) => tool.name);
  if (missing.length > 0) {
    throw new Error(`Registered MCP tools missing an outcome shape in tool-outcome.ts: ${missing.join(", ")}`);
  }
}

/** Decide whether a handler's result is the tool's success shape or a refusal. */
export function classifyToolOutcome(toolName: string, result: unknown, tool?: object): ToolOutcome {
  if (isProxiedTool(tool)) {
    // A proxied result is judged by the proxy's origin fact and never by parsing
    // its text; a result with no fact fails closed.
    const fact = proxiedOutcomeFact(result);
    return fact === undefined || fact.upstream_failed || fact.proxy_refusal ? "refusal" : "success";
  }
  // A tool absent from the registry gets the strict rule, because custom shapes
  // only widen it; production never reaches this, since startup refuses an
  // unregistered tool.
  const shape: ToolOutcomeShape = Object.hasOwn(TOOL_OUTCOME_SHAPES, toolName)
    ? TOOL_OUTCOME_SHAPES[toolName]!
    : "standard";
  const accepts = shape === "standard" ? standardOutcome : OUTCOME_PREDICATES[shape];
  return accepts(result) ? "success" : "refusal";
}

/**
 * The operator-side cause of a refusal decided while preparing a tool's
 * approval-target arguments, chosen by error type and never by message text.
 * Must match the argument-stage cause entries of DENIAL_CAUSES in
 * agent-native/denial-ledger.ts; narrowing a cause here needs no router edit.
 */
// DEBT(AGENT-SEAT-CI-DEFERRED-CAUSES): three operator-side ledger causes have no producer yet; the agent-facing refusal is unaffected.
// They are an unbound-session cause at this stage (recorded as pre_gate_argument_refused, since the
// session-identity error is also raised for a handle that is not the caller's), an unresolved-origin
// cause for a write whose origin cannot be determined, and pre-gate refusals for the events, audit
// search and compound tools in a session with no identity (they reach the gate first today). Only
// the operator ledger is less specific; the agent sees the same refusal either way.
export function argumentStageCause(error: unknown): Extract<DenialCause, "export_capacity" | "pre_gate_argument_refused"> {
  return isNamespaceDiscoveryLimitError(error) ? "export_capacity" : "pre_gate_argument_refused";
}

/**
 * The operator-side facts of a refused handler result: the top-level verdict
 * key and value of its body, and the committed and audited flags a handler
 * reports when its effect already happened. Reads only the top level; never
 * parses deeper.
 */
export function refusedResultFacts(result: unknown): {
  error_name: string;
  error_message?: string;
  facts?: Record<string, boolean>;
} {
  const texts = typeof result === "object" && result !== null && Array.isArray((result as { content?: unknown }).content)
    ? ((result as { content: unknown[] }).content)
      .map((item) => (typeof item === "object" && item !== null ? (item as { text?: unknown }).text : undefined))
    : [];
  const first = texts.length === 1 && typeof texts[0] === "string" ? texts[0] : undefined;
  let body: unknown;
  if (first !== undefined) {
    try { body = JSON.parse(first); } catch { body = undefined; }
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) return { error_name: "shape" };
  const record = body as Record<string, unknown>;
  const facts: Record<string, boolean> = {};
  for (const key of ["committed", "audited"] as const) {
    if (typeof record[key] === "boolean") facts[key] = record[key] as boolean;
  }
  const withFacts = Object.keys(facts).length > 0 ? { facts } : {};
  for (const key of ["error", "denied", "status"] as const) {
    if (Object.hasOwn(record, key)) {
      const value = record[key];
      return { error_name: key, error_message: typeof value === "string" ? value : JSON.stringify(value), ...withFacts };
    }
  }
  return { error_name: (result as { isError?: unknown }).isError === true ? "is_error" : "shape", ...withFacts };
}
