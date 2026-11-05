import type { IdentityManager } from "../cognitive/tools.js";
import type { StateStore } from "../cognitive/state-store.js";
import type { ResponseScreen } from "../proxy/response-screen.js";
import { resolveActiveSessionIdentity, type SessionBinding } from "./safety-base.js";
import { protectionEvidenceSchema, type ProtectionObservationSnapshot } from "./protection-layers.js";

/** Local runtime objects, resolved again for each home, follower and stream frame. */
export interface ProtectionRuntimeSources {
  identityManager?: IdentityManager | null;
  stateStore?: StateStore;
  responseScreen?: Pick<ResponseScreen, "assertReady">;
  currentSessionBinding?: () => SessionBinding | undefined;
}
/** No runtime observation is available; absence cannot establish construction or identity. */
export const protectionRuntimeUnavailable: Readonly<ProtectionRuntimeSources> = Object.freeze({});
/** Must match protectionRuntime in posture-routes.ts and dashboard/aggregator.ts; never capture stale dependencies. */
export type ProtectionRuntimeProvider = () => ProtectionRuntimeSources;
/** Panels retain the qualification established by their existing bounded producers. */
export type QualifiedProtectionPanels = Pick<ProtectionObservationSnapshot,
  "auditChain" | "featureHealth" | "custodyExit" | "custodyObservation" | "now">;

/** Observe the bound session and local consumers without loading storage or manufacturing evidence. */
export function observeProtections(runtime: ProtectionRuntimeSources, panels: QualifiedProtectionPanels): ProtectionObservationSnapshot {
  let identityLoaded: boolean | undefined;
  try {
    // The subject is the validated session, never the primary identity; the loaded manager supplies existence only.
    const subject = resolveActiveSessionIdentity(runtime.currentSessionBinding?.());
    const identityManager = runtime.identityManager;
    if (identityManager) identityLoaded = identityManager.get(subject.identity_id) !== undefined;
  } catch {
    // Failed or absent lookup cannot establish either presence or absence of this subject's keys.
    identityLoaded = undefined;
  }
  let encryptedStateStoreConstructed: boolean | undefined;
  try {
    // Only the actual constructed consumer proves the runtime claim; raw storage does not.
    encryptedStateStoreConstructed = runtime.stateStore ? true : undefined;
  } catch {
    encryptedStateStoreConstructed = undefined;
  }
  let toolOutputScreenReady: boolean | undefined;
  try {
    const screen = runtime.responseScreen;
    if (screen) {
      try { screen.assertReady(); toolOutputScreenReady = true; }
      catch { toolOutputScreenReady = false; }
    }
  } catch {
    toolOutputScreenReady = undefined;
  }
  // Must match protectionEvidenceSchema in protection-layers.ts; unknown stays explicit at every surface.
  const snapshot: ProtectionObservationSnapshot = {
    identityLoaded,
    encryptedStateStoreConstructed,
    toolOutputScreenReady,
    auditChain: panels.auditChain,
    featureHealth: panels.featureHealth,
    custodyExit: panels.custodyExit,
    custodyObservation: panels.custodyObservation,
    now: panels.now,
  };
  protectionEvidenceSchema.parse(snapshot);
  return snapshot;
}

interface HomeObservation {
  snapshot: ProtectionObservationSnapshot;
  runtime: ProtectionRuntimeProvider;
  now: () => number;
}
// Weak ownership follows the exact home lifetime, with no serialized fields or retained history.
const homeObservations = new WeakMap<object, HomeObservation>();

/** Associate only completed home objects; must match buildHome and reconcilePostureHomeJoiner in posture-routes.ts. */
export function associateProtectionHome(home: object, observation: HomeObservation): void {
  homeObservations.set(home, observation);
}

/** Re-observe current runtime sources while preserving the caller's capped panel qualifications. */
export function observeProtectionJoiner(home: object, panels: Omit<QualifiedProtectionPanels, "now">): HomeObservation {
  const prior = homeObservations.get(home);
  const runtime = prior?.runtime ?? (() => protectionRuntimeUnavailable);
  const now = prior?.now ?? Date.now;
  const snapshot = observeProtections(runtime(), { ...panels, now: now() });
  return { snapshot, runtime, now };
}
