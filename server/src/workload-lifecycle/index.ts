/**
 * Sanctuary — Workload Lifecycle audit schema.
 *
 * Public surface: "workload lifecycle audit". The first adopted slice of the
 * workload-lifecycle audit schema (design + adversarial review, 2026-06-12):
 * versioned, signed, chain-bound lifecycle events for declared stateful
 * workloads, plus the agent-contract audit-log seal that emits them.
 *
 * SCOPE of this slice (deliberately bounded, stated honestly):
 *   - The schema module and the `sealLifecycleEmission` capability are complete
 *     and exercised by tests.
 *   - The Tier-B adapter can seal when given a `lifecycle_seal`, but NO
 *     production bootstrap path in this repo wires one yet. Turning the seal on
 *     for real workloads (wrapped sessions, VM boxes) is the design's separate
 *     I3/I4 build items, which the adversarial review re-pointed; they are NOT
 *     in this slice. So today: the mechanism exists and is opt-in; "Sanctuary
 *     audits mind hosting" remains "designed and in build," never "shipped."
 *   - Per-entry external verification (Merkle inclusion proofs), the consent-
 *     record store, the registry fold, and off-host anchoring are each their
 *     own later build items and are NOT claimed here.
 */

export {
  WORKLOAD_LIFECYCLE_OPS,
  WORKLOAD_LIFECYCLE_OP_VALUES,
  WORKLOAD_LIFECYCLE_SCHEMA,
  WORKLOAD_CONSENT_SCHEMA,
  WORKLOAD_CLASS_DEFINITION,
  STATE_TO_LIFECYCLE_OP,
  isWorkloadLifecycleOp,
  lifecycleOpForState,
  type WorkloadLifecycleOp,
  type WorkloadLifecycleSchema,
} from "./constants.js";

export {
  WorkloadLifecycleSchemaError,
  validateWorkloadLifecyclePayload,
  emitWorkloadLifecycle,
  signedEventHash,
  type WorkloadLifecyclePayload,
  type LifecycleInitiator,
  type LifecycleLineage,
  type DeleteOverride,
  type ConsentStatus,
  type StateDisposition,
  type InitiatorKind,
  type EmitWorkloadLifecycleParams,
} from "./payload.js";

export {
  sealLifecycleEmission,
  type LifecycleSealContext,
  type LifecycleSealInput,
} from "./seal.js";

export {
  WorkloadRegistry,
  type WorkloadRecord,
  type WorkloadLifecycleState,
} from "./registry.js";

export {
  buildHostWorkloadAttestation,
  classifyConsent,
  hostAttestationSigningBytes,
  hostAttestationBundleHash,
  verifyHostWorkloadAttestation,
  HostWorkloadAttestationError,
  WORKLOAD_HOST_ATTESTATION_SCHEMA,
  WORKLOAD_HOST_ATTESTATION_DOMAIN,
  WORKLOAD_HOST_ATTESTATION_SCOPE_TEXT,
  WORKLOAD_HOST_ATTESTATION_SIGNATURE_ALGORITHM,
  WORKLOAD_HOST_ATTESTATION_PAYLOAD_ENCODING,
  type AttestedWorkload,
  type HostWorkloadAttestationBody,
  type SignedHostWorkloadAttestation,
  type HostWorkloadAttestationTrust,
  type WorkloadAttestationSigner,
  type BuildHostWorkloadAttestationParams,
} from "./host-attestation.js";

export {
  sealHostAttestation,
  HostAttestationSealError,
  type HostAttestationSealContext,
} from "./host-attestation-seal.js";

export {
  recordWrappedHarnessRegistration,
  type RecordWrappedHarnessRegistrationParams,
} from "./wrap-registration.js";
