/**
 * Sanctuary Honeypot - Public surface.
 *
 * Sentinels honeypot authoring + runtime. Operator writes a trap in
 * plain English; the compiler maps it to a structured TrapSpec; the
 * registry holds the live trap set; runtime handlers fire findings on
 * matched access; the trap store persists specs encrypted at rest
 * (per-fortress HKDF subkey, AAD-bound to trap_id).
 *
 * Trap classes: http_endpoint, filesystem, tool_call, credential.
 * Trap findings route through the existing Phi-1 sentinel finding
 * store; trap responses are server-local (no outbound surface from the
 * trap path itself). The compile call is the only outbound-capable
 * step and rides the canonical template-suggestion LLM channel.
 *
 * runtime-trap-handler re-exports the compiler's CompileResult type;
 * this barrel re-exports that file by name (omitting the duplicate
 * CompileResult, which is surfaced by honeypot-compiler.js) so the two
 * star-exports do not collide.
 */

export * from "./types.js";
export * from "./trap-spec-validation.js";
export * from "./trap-registry.js";
export * from "./trap-store.js";
export * from "./honeypot-compiler.js";
export {
  HONEYPOT_API_PREFIX,
  handleHoneypotTriggerIfMatch,
  handleHoneypotRoute,
  type HoneypotTriggerDeps,
  type HoneypotRouterDeps,
} from "./runtime-trap-handler.js";
export * from "./filesystem-trap-monitor.js";
export * from "./tool-call-trap-runtime.js";
export * from "./credential-trap-runtime.js";
export * from "./cli.js";
