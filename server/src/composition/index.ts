/**
 * Sanctuary Composition v1.0 -- Public Surface
 *
 * Opt-in Concordia + Verascore composition. Default off.
 * Structural moat invariant: framework alone = fully operational.
 *
 * Scope lock: WP-MVP-10
 * Architecture walkthrough: Q4 (Concordia intra-mesh composition)
 */

export * from "./constants.js";
export * from "./types.js";
export * from "./errors.js";
export { resolveCompositionConfig, isCompositionDisabled } from "./composition-config.js";
export type { CompositionConfigInput } from "./composition-config.js";
export { SidecarManager } from "./sidecar-manager.js";
export type { SidecarState, SidecarEventListener } from "./sidecar-manager.js";
export { SidecarRpcClient } from "./sidecar-rpc.js";
export { packConcordiaReceipt, verifyConcordiaReceipt, verifyMandate } from "./concordia-adapter.js";
export { publishVerascoreSignal, getPublishedSignals, clearPublishedSignals } from "./verascore-hook.js";
export { DegradeMonitor } from "./degrade-monitor.js";
export type { DegradeStateChangeEvent, DegradeStateChangeListener } from "./degrade-monitor.js";
export { CompositionService } from "./composition-service.js";
