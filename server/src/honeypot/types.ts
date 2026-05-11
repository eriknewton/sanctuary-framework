/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-1 Honeypot Authoring types + audit ops.
 *
 * OPENS WP-V1.3-5 Honeypot Authoring. Operator writes a honeypot in
 * plain English; the compiler maps the English to a structured
 * TrapSpec; the runtime registers trap-handlers in the dashboard
 * route table; trap activations emit `honeypot_triggered` audit
 * events AND sentinel findings (Pi-1 reuses Phi-1's finding store so
 * traps surface in the existing sentinel UX).
 *
 * Pi-1 ships the http_endpoint trap class only; Pi-2 adds filesystem,
 * Pi-3 adds tool_call, Pi-4 adds credential. Architectural shape:
 * TrapSpec is a discriminated union keyed by `trap_class` so new
 * trap classes extend by adding a union arm + a runtime handler.
 *
 * Castle-walking discipline:
 *  - Trap responses are server-local (404 or 500 returned to the
 *    caller). No outbound surface from the trap path itself.
 *  - The compile call routes through the substrate selector at the
 *    `template-suggestion` surface (canonical outbound LLM channel
 *    for template-shape generation; Rho-1 header strip applies).
 *  - Trap findings route through the Phi-1 finding store, the
 *    existing canonical pipeline for Castle Layer 2 observability.
 */

import type { SentinelSeverity } from "../sentinel/types.js";

/** Operator-friendly trap class enum. */
export type TrapClass =
  | "http_endpoint"   // Pi-1 (this PR)
  | "filesystem"      // Pi-2
  | "tool_call"       // Pi-3
  | "credential";     // Pi-4

/**
 * HTTP-endpoint trap trigger. The runtime matches incoming requests
 * against `path_pattern` (glob-style with `*` and `**`); `method`
 * narrows to a specific HTTP method when set, otherwise any method
 * fires. `expected_caller_types` is operator-recorded metadata that
 * surfaces in the finding's evidence; the runtime does not gate on
 * it (caller identity is observed, not constrained, at the trap
 * boundary).
 */
export interface HttpEndpointTrigger {
  path_pattern: string;
  method?: string;
  expected_caller_types: string[];
}

/**
 * One compiled trap. Persisted by the registry, deployed to the
 * runtime route table, and used by the finding emitter when a trap
 * triggers. Pi-1 ships the http_endpoint class only; Pi-2+ extend
 * via the `trigger` discriminator.
 */
export interface TrapSpec {
  trap_id: string;
  trap_class: TrapClass;
  trigger: HttpEndpointTrigger;
  finding_severity: SentinelSeverity;
  english_text: string;
  explanation_paragraph: string;
  compiled_at: string;
}

/**
 * Operator's English draft of a honeypot. The compiler produces a
 * TrapSpec from this input via the substrate selector.
 */
export interface HoneypotDraft {
  english_text: string;
  operator_id: string;
  observed_at: string;
}

/**
 * Audit operations the honeypot subsystem emits. Stable strings so
 * downstream consumers (activity feed, dashboard inbox, soak drill)
 * can branch on them without parsing free text.
 *
 * DRAFTED:     operator submits English to /api/honeypot/compile.
 * COMPILED:    compiler returns a TrapSpec (success or fallback).
 * DEPLOYED:    operator activates the TrapSpec at runtime.
 * TRIGGERED:   trap detected an access. One event per matched call.
 * UNDEPLOYED:  TrapSpec removed from the runtime.
 */
export const HONEYPOT_AUDIT_OPS = {
  DRAFTED: "honeypot_drafted",
  COMPILED: "honeypot_compiled",
  DEPLOYED: "honeypot_deployed",
  TRIGGERED: "honeypot_triggered",
  UNDEPLOYED: "honeypot_undeployed",
} as const;

export type HoneypotAuditOp =
  (typeof HONEYPOT_AUDIT_OPS)[keyof typeof HONEYPOT_AUDIT_OPS];

/**
 * Sentinel-id prefix the finding emitter uses for honeypot triggers.
 * Findings surface in Phi-1's sentinel UX under
 * `honeypot:<trap_id>` so operators can filter by trap when many
 * are deployed.
 */
export const HONEYPOT_SENTINEL_ID_PREFIX = "honeypot:" as const;

/** Compute the sentinel id for a trap. Pure helper. */
export function honeypotSentinelId(trapId: string): string {
  return `${HONEYPOT_SENTINEL_ID_PREFIX}${trapId}`;
}
