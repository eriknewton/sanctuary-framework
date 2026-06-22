/**
 * Sanctuary — Host workload attestation SEAL.
 *
 * Appends a signed {@link SignedHostWorkloadAttestation} to the audit chain as
 * a CRITICAL, durability-verified, hash-chained entry. The chain record IS the
 * durable attestation artifact (no new persistent store is added — constraint
 * carried from #504).
 *
 * COMPOSES with #504:
 *   - It writes under the additive `WORKLOAD_LIFECYCLE_OPS.HOST_ATTESTED`
 *     operation, so an auditor folding the lifecycle vocabulary sees attestation
 *     events in the same set as instantiate/sleep/delete.
 *   - It does NOT route through `emitWorkloadLifecycle`: that writer validates a
 *     per-workload `WorkloadLifecyclePayload`, which an attestation is not. The
 *     attestation is a distinct artifact, appended directly via `appendCritical`
 *     with its own bound digest — mirroring how a checkpoint is chain-bound
 *     without being a lifecycle payload. The `HOST_ATTESTED` op therefore never
 *     reaches the lifecycle payload validator, and a test asserts the registry
 *     fold ignores it (it is not a per-workload state transition).
 *
 * Binding: the audit entry's `details.attestation_bundle_sha256` is the sha256
 * over the domain-separated canonical bytes of the WHOLE signed envelope (body
 * + signature), the same `hostAttestationBundleHash` a second reader recomputes.
 * This mirrors `sealLifecycleEmission` binding a lifecycle entry to its mesh
 * event by `signed_event_hash`: the chain entry commits to exactly this bundle.
 *
 * Privacy: the chain `details` carries the bundle hash, the signer kid, the
 * compliant flag, the declared-workload count, and the scope text — NOT raw
 * consent bodies (there are none; #504 keeps consent records out of band, only
 * a `consent_ref` is ever recorded). No workload content enters the entry.
 */

import type { AuditEntryInput, AuditLog } from "../operational/audit-log.js";
import { WORKLOAD_LIFECYCLE_OPS } from "./constants.js";
import {
  hostAttestationBundleHash,
  WORKLOAD_HOST_ATTESTATION_SCHEMA,
  type SignedHostWorkloadAttestation,
} from "./host-attestation.js";

/** Standing context the seal needs (the recording fortress/identity). */
export interface HostAttestationSealContext {
  /** Audit `identity_id` field — the fortress/identity recording the entry. */
  recording_identity_id: string;
  /** Optional explicit timestamp for the audit entry (defaults to now). */
  timestamp?: string;
}

/**
 * Seal a signed host attestation into the audit chain.
 *
 * Returns the bundle hash the entry was bound to (so a caller can cross-check a
 * later chain walk). Throws on a persistence failure (the underlying
 * `appendCritical` contract) — never silently degrades.
 */
export async function sealHostAttestation(
  auditLog: AuditLog,
  attestation: SignedHostWorkloadAttestation,
  ctx: HostAttestationSealContext
): Promise<string> {
  const bundleHash = hostAttestationBundleHash(attestation);
  const entry: AuditEntryInput = {
    layer: "l2",
    operation: WORKLOAD_LIFECYCLE_OPS.HOST_ATTESTED,
    identity_id: ctx.recording_identity_id,
    result: "success",
    details: {
      attestation_schema: WORKLOAD_HOST_ATTESTATION_SCHEMA,
      // The binding digest a second reader recomputes from the bundle.
      attestation_bundle_sha256: bundleHash,
      signer_kid: attestation.signer_kid,
      fortress_id: attestation.body.fortress_id,
      attested_at: attestation.body.attested_at,
      // Summary fields (no consent bodies, no workload content) so an operator
      // querying the chain sees the disposition without recomputing the bundle.
      declared_workload_count: attestation.body.workloads.length,
      compliant: attestation.body.compliant,
      manufactured_preference_caveat:
        attestation.body.manufactured_preference_caveat,
      // The honesty-scoping text travels into the chain record too, so a chain
      // reader cannot interpret the attestation as host-wide-complete.
      scope: attestation.body.scope,
    },
    ...(ctx.timestamp ? { timestamp: ctx.timestamp } : {}),
  };
  await auditLog.appendCritical(entry);
  return bundleHash;
}
