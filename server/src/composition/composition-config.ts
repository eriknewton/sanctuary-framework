/**
 * Sanctuary Composition v1.0 -- Config
 *
 * Reads fortress-config toggle, enforces default-off, validates
 * Verascore scope settings. Composition is OFF by default.
 *
 * Structural moat invariant: when composition_enabled = false,
 * zero Concordia or Verascore code paths are reachable.
 */

import { join } from "node:path";
import { COMPOSITION_DEFAULTS, VERASCORE_SCOPES, type VerascoreScope } from "./constants.js";
import type { CompositionConfig } from "./types.js";

/**
 * Input shape from fortress config (operator-provided, partial).
 * All fields optional; defaults are applied.
 */
export interface CompositionConfigInput {
  composition_enabled?: boolean;
  verascore_default_scope?: string;
  sidecar_script_path?: string;
  python_path?: string;
  sidecar_spawn_timeout_ms?: number;
  sidecar_rpc_timeout_ms?: number;
  sidecar_restart_initial_delay_ms?: number;
  sidecar_restart_max_delay_ms?: number;
  sidecar_restart_backoff_multiplier?: number;
  sidecar_max_consecutive_crashes?: number;
  replay_queue_max_depth?: number;
}

/**
 * Resolve a complete CompositionConfig from partial operator input.
 * Enforces default-off and validates Verascore scope.
 *
 * @param input Partial config from fortress config file
 * @param basePath Base path for resolving relative sidecar paths
 * @returns Complete, validated CompositionConfig
 */
export function resolveCompositionConfig(
  input?: CompositionConfigInput,
  basePath?: string
): CompositionConfig {
  const enabled = input?.composition_enabled ?? COMPOSITION_DEFAULTS.ENABLED;

  // Validate Verascore scope
  const rawScope = input?.verascore_default_scope ?? COMPOSITION_DEFAULTS.VERASCORE_SCOPE;
  if (!(VERASCORE_SCOPES as readonly string[]).includes(rawScope)) {
    throw new Error(
      `Invalid verascore_default_scope "${rawScope}". Must be one of: ${VERASCORE_SCOPES.join(", ")}`
    );
  }
  const scope = rawScope as VerascoreScope;

  // Default sidecar paths relative to basePath
  const defaultBase = basePath ?? process.cwd();
  const defaultSidecarPath = join(defaultBase, "sidecars", "concordia", "sidecar.py");
  const defaultPythonPath = join(defaultBase, "sidecars", "concordia", ".venv", "bin", "python");

  return {
    composition_enabled: enabled,
    verascore_default_scope: scope,
    sidecar_script_path: input?.sidecar_script_path ?? defaultSidecarPath,
    python_path: input?.python_path ?? defaultPythonPath,
    sidecar_spawn_timeout_ms:
      input?.sidecar_spawn_timeout_ms ?? COMPOSITION_DEFAULTS.SIDECAR_SPAWN_TIMEOUT_MS,
    sidecar_rpc_timeout_ms:
      input?.sidecar_rpc_timeout_ms ?? COMPOSITION_DEFAULTS.SIDECAR_RPC_TIMEOUT_MS,
    sidecar_restart_initial_delay_ms:
      input?.sidecar_restart_initial_delay_ms ?? COMPOSITION_DEFAULTS.SIDECAR_RESTART_INITIAL_DELAY_MS,
    sidecar_restart_max_delay_ms:
      input?.sidecar_restart_max_delay_ms ?? COMPOSITION_DEFAULTS.SIDECAR_RESTART_MAX_DELAY_MS,
    sidecar_restart_backoff_multiplier:
      input?.sidecar_restart_backoff_multiplier ?? COMPOSITION_DEFAULTS.SIDECAR_RESTART_BACKOFF_MULTIPLIER,
    sidecar_max_consecutive_crashes:
      input?.sidecar_max_consecutive_crashes ?? COMPOSITION_DEFAULTS.SIDECAR_MAX_CONSECUTIVE_CRASHES,
    replay_queue_max_depth:
      input?.replay_queue_max_depth ?? COMPOSITION_DEFAULTS.REPLAY_QUEUE_MAX_DEPTH,
  };
}

/**
 * Check if composition is structurally disabled.
 * When this returns true, NO composition module should be loaded or invoked.
 */
export function isCompositionDisabled(config: CompositionConfig): boolean {
  return !config.composition_enabled;
}

/**
 * Validate that the Verascore scope is not silently set to public.
 * Public publish requires explicit per-commitment opt-in.
 * This function is used at config resolution time as a safety check.
 */
export function validateVerascoreScope(scope: VerascoreScope): void {
  // At v1.0, the default scope must be "private".
  // "public" as a default is a STOP condition per spawn prompt.
  // Operator can override per-commitment, but the default stays private.
  if (scope !== "private") {
    throw new Error(
      `Verascore default scope is "${scope}" but must be "private" at v1.0. ` +
      `Public publish requires per-commitment explicit opt-in.`
    );
  }
}
