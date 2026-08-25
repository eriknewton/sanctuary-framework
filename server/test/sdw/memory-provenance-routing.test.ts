import { describe, expect, it } from "vitest";
import type { MemoryProvenanceCompanion } from "../../src/sdw/memory-provenance-contract.js";
import {
  clusterMemoryProvenanceForContext,
  isMemoryProvenanceOutboundSyncEligible,
} from "../../src/sdw/memory-provenance-routing.js";

function companion(tier: "local_attested" | "foreign_direct" | "foreign_relayed" | "legacy_unattested", lineage: string, signer: string): MemoryProvenanceCompanion {
  return {
    format: "SANCTUARY_SDW_MEMORY_PROVENANCE_V1",
    origin_provenance_digest: "a".repeat(64),
    origin: { body: {
      format: "SANCTUARY_SDW_MEMORY_ORIGIN_V1", origin_fortress_id: "fortress-a",
      owner_ref: "owner", passage_id: "passage", content_hash: "b".repeat(64), chunk_count: 1,
      author_agent_id: "agent", ingress_channel: "memory_insert", source_class: "user_content",
      recorded_at: "2026-08-24T12:00:00.000Z", signer_identity_id: signer, signer_did: signer,
      signature_scheme: "ed25519-v1",
    }, signature: "origin-signature" },
    admission: { body: {
      format: "SANCTUARY_SDW_MEMORY_ADMISSION_V1", origin_provenance_digest: "a".repeat(64),
      destination_fortress_id: "fortress-b", destination_owner_ref: "owner", passage_id: "passage",
      admission_channel: tier === "local_attested" ? "local_write" : tier === "legacy_unattested" ? "exit_v2_import" : "exit_v2_import",
      origin_trust_tier: tier,
      verification_basis: tier === "local_attested" ? "local_primary_identity" : tier === "legacy_unattested" ? "exit_v2_legacy_v1" : tier === "foreign_direct" ? "exit_v2_manifest_key" : "exit_v2_known_signers",
      admitted_at: "2026-08-24T13:00:00.000Z", transfer_lineage_ref: lineage,
      signer_identity_id: "destination", signer_did: "destination", signature_scheme: "ed25519-v1",
    }, signature: `admission-${lineage}` },
  } as MemoryProvenanceCompanion;
}

describe("C4 provenance routing", () => {
  it("has one fail-closed outbound-sync predicate", () => {
    const foreign = companion("foreign_direct", "lineage", "signer");
    expect(isMemoryProvenanceOutboundSyncEligible({ state: "state_COMPLETE", companionVerified: true, companion: foreign, quarantined: false })).toBe(true);
    expect(isMemoryProvenanceOutboundSyncEligible({ state: "state_MIGRATING", companionVerified: true, companion: foreign, quarantined: false })).toBe(false);
    expect(isMemoryProvenanceOutboundSyncEligible({ state: "state_COMPLETE", companionVerified: true, companion: companion("legacy_unattested", "legacy", "signer"), quarantined: false })).toBe(false);
  });

  it("groups by admission lineage before mintable signer DID and retains quarantine vectors", () => {
    const result = clusterMemoryProvenanceForContext([
      { companion: companion("foreign_direct", "same-lineage", "did:key:one"), quarantined: false },
      { companion: companion("foreign_direct", "same-lineage", "did:key:two"), quarantined: true },
    ]);
    expect(result.primaryGrouping).toBe("admission_lineage");
    expect(result.clusterCount).toBe(1);
    expect(result.largestClusterSize).toBe(2);
    expect(result.quarantinedVectorCount).toBe(1);
  });
});
