import type { CompiledContextProvenanceClustering } from "../compiled-context/types.js";
import type { SdwMemoryIntegrityState } from "./records.js";
import type { MemoryProvenanceCompanion } from "./memory-provenance-contract.js";

/** The one C4 predicate every future outbound-sync producer must call. */
export function isMemoryProvenanceOutboundSyncEligible(input: {
  readonly state: SdwMemoryIntegrityState;
  readonly companionVerified: boolean;
  readonly companion: MemoryProvenanceCompanion;
  readonly quarantined: boolean;
}): boolean {
  return input.state === "state_COMPLETE" &&
    input.companionVerified &&
    !input.quarantined &&
    input.companion.admission.body.origin_trust_tier !== "legacy_unattested";
}

export interface MemoryProvenanceClusterCandidate {
  readonly companion: MemoryProvenanceCompanion;
  /** Quarantine excludes text, not its bounded detector vector. */
  readonly quarantined: boolean;
}

/**
 * Admission and transfer ancestry outrank signer identity because DIDs are
 * mintable. The returned aggregate carries no text or raw provenance bytes.
 */
export function clusterMemoryProvenanceForContext(
  candidates: readonly MemoryProvenanceClusterCandidate[],
): CompiledContextProvenanceClustering {
  const clusters = new Map<string, number>();
  const origins = new Set<string>();
  for (const { companion } of candidates) {
    const { origin, admission } = companion;
    origins.add(origin.body.origin_fortress_id);
    const key = admission.body.transfer_lineage_ref ?? [
      admission.signature,
      origin.body.origin_fortress_id,
      origin.body.author_agent_id,
      origin.body.source_class,
      origin.body.recorded_at.slice(0, 13),
      origin.body.signer_did,
    ].join("\u0000");
    clusters.set(key, (clusters.get(key) ?? 0) + 1);
  }
  return {
    version: "sanctuary.memory-provenance-clustering.v1",
    primaryGrouping: "admission_lineage",
    clusterCount: clusters.size,
    largestClusterSize: Math.max(0, ...clusters.values()),
    distinctOriginCount: origins.size,
    quarantinedVectorCount: candidates.filter((candidate) => candidate.quarantined).length,
  };
}
