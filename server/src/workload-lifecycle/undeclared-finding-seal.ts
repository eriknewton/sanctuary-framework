/**
 * Sanctuary — Undeclared-workload finding SEAL.
 *
 * Appends a signed {@link SignedUndeclaredFinding} to the audit chain as a
 * CRITICAL, durability-verified, hash-chained entry. The chain record IS the
 * durable finding artifact (no new persistent store is added — constraint
 * carried from #504/#513).
 *
 * COMPOSES with #504/#513 (additive), mirroring `sealHostAttestation`:
 *   - It writes under the additive `WORKLOAD_LIFECYCLE_OPS.UNDECLARED_DETECTED`
 *     operation, so an auditor folding the lifecycle vocabulary sees detection
 *     findings in the same set as instantiate/sleep/delete/attest.
 *   - It does NOT route through `emitWorkloadLifecycle`: that writer validates a
 *     per-workload `WorkloadLifecyclePayload`, which a host-level detection
 *     finding is not. The finding is a distinct artifact, appended directly via
 *     `appendCritical` with its own bound digest — exactly like the host
 *     attestation seal. The `UNDECLARED_DETECTED` op therefore never reaches the
 *     lifecycle payload validator, and (like `HOST_ATTESTED`) it is excluded from
 *     the registry's per-workload state fold; a test asserts the registry fold
 *     ignores it.
 *
 * Binding: the audit entry's `details.finding_bundle_sha256` is the sha256 over
 * the domain-separated canonical bytes of the WHOLE signed envelope (body +
 * signature), the same `undeclaredFindingBundleHash` a second reader recomputes.
 * This mirrors `sealHostAttestation` binding the entry to its attestation bundle.
 *
 * Privacy: the chain `details` carries the bundle hash, the signer kid, the
 * counts, and the scope text — plus the flagged `agent_id`s (operational
 * identifiers, NOT workload content; no consent bodies, no state content). No
 * raw workload state enters the entry.
 */

import type { AuditEntryInput, AuditLog } from "../operational/audit-log.js";
import { WORKLOAD_LIFECYCLE_OPS } from "./constants.js";
import {
  undeclaredFindingBundleHash,
  verifyUndeclaredFinding,
  WORKLOAD_UNDECLARED_FINDING_SCHEMA,
  type SignedUndeclaredFinding,
} from "./undeclared-finding.js";

/** Thrown when the seal REFUSES to bind a finding whose signature does not
 * verify (fail-closed: constraint #5, never silently degrade to sealing an
 * unauthenticated bundle). */
export class UndeclaredFindingSealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UndeclaredFindingSealError";
  }
}

/** Standing context the seal needs (the recording fortress/identity). */
export interface UndeclaredFindingSealContext {
  /** Audit `identity_id` field — the fortress/identity recording the entry. */
  recording_identity_id: string;
  /** Optional explicit timestamp for the audit entry (defaults to now). */
  timestamp?: string;
  /**
   * The out-of-band trusted public key the finding MUST verify under before it is
   * sealed (mirrors #513 FIX-4). When set, a bundle forged under any other key is
   * REJECTED (the seal throws and writes nothing). When ABSENT, the seal still
   * refuses to bind a bundle whose signature does not verify against its OWN
   * self-declared `public_key` (verify-before-seal); but WITHOUT a trusted key it
   * cannot distinguish a self-signed forgery from a genuine one, so a caller that
   * needs origin authentication MUST supply `trustedPublicKey`.
   */
  trustedPublicKey?: string | Uint8Array;
}

/**
 * Seal a signed undeclared finding into the audit chain.
 *
 * Verify-before-seal (mirrors #513 FIX-4): the signature is verified BEFORE the
 * entry is bound; a bundle whose signature does not verify is REJECTED (throws
 * {@link UndeclaredFindingSealError}, writes nothing). Supply
 * `ctx.trustedPublicKey` to pin the accepted signer and reject a forged
 * suppression finding; without it the check is self-consistency only.
 *
 * Returns the bundle hash the entry was bound to (so a caller can cross-check a
 * later chain walk). Throws on a persistence failure (the underlying
 * `appendCritical` contract), never silently degrades.
 */
export async function sealUndeclaredFinding(
  auditLog: AuditLog,
  finding: SignedUndeclaredFinding,
  ctx: UndeclaredFindingSealContext,
): Promise<string> {
  // Verify-before-seal: never bind a finding whose signature does not verify.
  // With a trusted key, this also rejects a self-signed forgery.
  const verified = verifyUndeclaredFinding(
    finding,
    finding.public_key,
    ctx.trustedPublicKey !== undefined
      ? { trustedPublicKey: ctx.trustedPublicKey }
      : undefined,
  );
  if (!verified) {
    throw new UndeclaredFindingSealError(
      "refusing to seal an undeclared finding whose signature does not verify" +
        (ctx.trustedPublicKey !== undefined
          ? " against the trusted signer key"
          : " against its own public key") +
        "; nothing was written",
    );
  }
  const bundleHash = undeclaredFindingBundleHash(finding);
  const entry: AuditEntryInput = {
    layer: "l2",
    operation: WORKLOAD_LIFECYCLE_OPS.UNDECLARED_DETECTED,
    identity_id: ctx.recording_identity_id,
    result: "success",
    details: {
      finding_schema: WORKLOAD_UNDECLARED_FINDING_SCHEMA,
      // The binding digest a second reader recomputes from the bundle.
      finding_bundle_sha256: bundleHash,
      signer_kid: finding.signer_kid,
      fortress_id: finding.body.fortress_id,
      attested_at: finding.body.attested_at,
      // Summary fields (no workload state content) so an operator querying the
      // chain sees the disposition without recomputing the bundle.
      undeclared_count: finding.body.undeclared_count,
      live_count: finding.body.live_count,
      declared_count: finding.body.declared_count,
      // The flagged operational identifiers (agent_ids only), for an at-a-glance
      // chain read. NOT workload content.
      undeclared_agent_ids: finding.body.undeclared.map((u) => u.agent_id),
      // The honesty-scoping text travels into the chain record too, so a chain
      // reader cannot interpret the finding as host-wide-complete.
      scope: finding.body.scope,
    },
    ...(ctx.timestamp ? { timestamp: ctx.timestamp } : {}),
  };
  await auditLog.appendCritical(entry);
  return bundleHash;
}
