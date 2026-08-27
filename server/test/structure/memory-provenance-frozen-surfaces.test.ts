import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  INTERNAL_SIGNING_DOMAIN_PREFIXES,
  MEMORY_ADMISSION_SIGNING_DOMAIN_PREFIX,
  MEMORY_ORIGIN_SIGNING_DOMAIN_PREFIX,
  startsWithInternalSigningDomain,
} from "../../src/core/signing-domains.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { MAX_MEMORY_PROVENANCE_SIGNERS } from "../../src/reputation/known-signers-store.js";
import { MEMORY_PROVENANCE_SIGNER_PREFIX } from "../../src/reputation/known-signers-store.js";
import { EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT_V2, EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2 } from "../../src/contracts/v1.2/exit-bundle-manifest.js";
import { MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETION_KEY } from "../../src/exit/bundle.js";
import {
  DISCLOSURE_CAPSULE_RETURN_AUTHOR_AGENT_ID,
  MAX_MEMORY_PROVENANCE_COMPANION_BYTES,
  MAX_MEMORY_PROVENANCE_SIGNER_ENTRIES,
  MEMORY_ADMISSION_CHANNELS,
  MEMORY_ADMISSION_FORMAT,
  MEMORY_ADMISSION_SIGNING_DOMAIN,
  MEMORY_ADMISSION_TRIPLES,
  MEMORY_EXTERNAL_DESTINATION_CLASSES,
  MEMORY_EXTERNAL_EVIDENCE_BASES,
  MEMORY_EXTERNAL_SOURCE_REF_FORMAT,
  MEMORY_EXTERNAL_SOURCE_TRIPLES,
  MEMORY_INGRESS_CHANNELS,
  MEMORY_INGRESS_SOURCE_PAIRS,
  MEMORY_ORIGIN_FORMAT,
  MEMORY_ORIGIN_SIGNING_DOMAIN,
  MEMORY_ORIGIN_TRUST_TIERS,
  MEMORY_PROVENANCE_COMPANION_FORMAT,
  MEMORY_SIGNATURE_SCHEME,
  MEMORY_SOURCE_CLASSES,
  MEMORY_VERIFICATION_BASES,
  memoryOriginSigningBytes,
  type MemoryOriginBody,
} from "../../src/sdw/memory-provenance-contract.js";
import {
  MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE_AUDIT,
  MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION,
  MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN_AUDIT,
} from "../../src/sdw/memory-provenance-signer-prune.js";

const memoryAttestSource = fileURLToPath(
  new URL("../../src/cognitive/memory-attest.ts", import.meta.url),
);

describe("C1 frozen memory-provenance surfaces", () => {
  it("pins both exact domain bytes on the contract and refusal-registry sides", () => {
    const expected = [
      "sanctuary.sdw.memory-origin.v1\n",
      "sanctuary.sdw.memory-admission.v1\n",
    ];
    expect([MEMORY_ORIGIN_SIGNING_DOMAIN, MEMORY_ADMISSION_SIGNING_DOMAIN]).toEqual(expected);
    expect([
      MEMORY_ORIGIN_SIGNING_DOMAIN_PREFIX,
      MEMORY_ADMISSION_SIGNING_DOMAIN_PREFIX,
    ]).toEqual(expected);
    for (const domain of expected) {
      expect(INTERNAL_SIGNING_DOMAIN_PREFIXES).toContain(domain);
      expect(startsWithInternalSigningDomain(stringToBytes(`${domain}{}`))).toBe(true);
    }
  });

  it("pins all version, enum, and exact admission-triple literals", () => {
    expect([
      MEMORY_PROVENANCE_COMPANION_FORMAT,
      MEMORY_ORIGIN_FORMAT,
      MEMORY_ADMISSION_FORMAT,
      MEMORY_EXTERNAL_SOURCE_REF_FORMAT,
      MEMORY_SIGNATURE_SCHEME,
    ]).toEqual([
      "SANCTUARY_SDW_MEMORY_PROVENANCE_V1",
      "SANCTUARY_SDW_MEMORY_ORIGIN_V1",
      "SANCTUARY_SDW_MEMORY_ADMISSION_V1",
      "SANCTUARY_SDW_MEMORY_EXTERNAL_SOURCE_REF_V1",
      "ed25519-v1",
    ]);
    expect(MAX_MEMORY_PROVENANCE_COMPANION_BYTES).toBe(16 * 1024);
    expect(MAX_MEMORY_PROVENANCE_SIGNER_ENTRIES).toBe(MAX_MEMORY_PROVENANCE_SIGNERS);
    expect(MEMORY_PROVENANCE_SIGNER_PREFIX).toBe("memprov.");
    expect([
      MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION,
      MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN_AUDIT,
      MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE_AUDIT,
      MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETION_KEY,
    ]).toEqual([
      "memory_provenance_prune_signers",
      "MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN",
      "MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE",
      "memory-provenance-signer-prune-v1",
    ]);
    expect([EXIT_V2_SDW_MEMORY_ARTIFACT_FORMAT_V2, EXIT_V2_SDW_MEMORY_PAYLOAD_FORMAT_V2]).toEqual([
      "SANCTUARY_EXIT_V2_SDW_MEMORY_ARCHIVE_V2",
      "SANCTUARY_EXIT_V2_SDW_MEMORY_LOGICAL_ARCHIVE_V2",
    ]);
    expect(MEMORY_ADMISSION_CHANNELS).toEqual([
      "local_write",
      "legacy_migration",
      "exit_v2_import",
      "fleet_sync",
      "operator_readmission",
    ]);
    expect(MEMORY_ORIGIN_TRUST_TIERS).toEqual([
      "local_attested",
      "legacy_unattested",
      "foreign_direct",
      "foreign_relayed",
    ]);
    expect(MEMORY_VERIFICATION_BASES).toEqual([
      "local_primary_identity",
      "legacy_local_observation",
      "exit_v2_manifest_key",
      "exit_v2_known_signers",
      "exit_v2_legacy_v1",
      "fleet_sync_manifest_key",
      "fleet_sync_known_signers",
      "operator_readmission_after_compromise",
    ]);
    expect(MEMORY_ADMISSION_TRIPLES).toEqual([
      { admission_channel: "local_write", origin_trust_tier: "local_attested", verification_basis: "local_primary_identity" },
      { admission_channel: "legacy_migration", origin_trust_tier: "legacy_unattested", verification_basis: "legacy_local_observation" },
      { admission_channel: "exit_v2_import", origin_trust_tier: "foreign_direct", verification_basis: "exit_v2_manifest_key" },
      { admission_channel: "exit_v2_import", origin_trust_tier: "foreign_relayed", verification_basis: "exit_v2_known_signers" },
      { admission_channel: "exit_v2_import", origin_trust_tier: "legacy_unattested", verification_basis: "exit_v2_legacy_v1" },
      { admission_channel: "fleet_sync", origin_trust_tier: "foreign_direct", verification_basis: "fleet_sync_manifest_key" },
      { admission_channel: "fleet_sync", origin_trust_tier: "foreign_relayed", verification_basis: "fleet_sync_known_signers" },
      { admission_channel: "operator_readmission", origin_trust_tier: "legacy_unattested", verification_basis: "operator_readmission_after_compromise" },
    ]);
  });

  it("pins all ingress/source literals and the exact eight-row pair table", () => {
    expect(MEMORY_INGRESS_CHANNELS).toEqual([
      "memory_insert",
      "anthropic_memory_tool",
      "file_import",
      "memory_transcode",
      "legacy_migration",
      "legacy_unknown",
      "fleet_sync",
      "disclosure_capsule_return",
    ]);
    expect(MEMORY_SOURCE_CLASSES).toEqual([
      "user_content",
      "agent_derived_clean",
      "system_generated",
      "claude_code_index",
      "claude_code_fact",
      "codex_index",
      "codex_summary",
      "codex_raw",
      "transcode_manifest",
      "transcode_source_file",
      "exit_lineage",
      "legacy_unattested",
      "fleet_sync_lineage",
      "provider_return_locally_observed",
      "tool_return_locally_observed",
      "peer_return_signed",
    ]);
    expect(MEMORY_INGRESS_SOURCE_PAIRS).toEqual({
      memory_insert: ["user_content", "agent_derived_clean", "system_generated"],
      anthropic_memory_tool: ["user_content", "agent_derived_clean", "system_generated"],
      file_import: ["claude_code_index", "claude_code_fact", "codex_index", "codex_summary", "codex_raw"],
      memory_transcode: ["transcode_manifest", "transcode_source_file", "exit_lineage"],
      legacy_migration: ["legacy_unattested"],
      legacy_unknown: ["legacy_unattested"],
      fleet_sync: ["fleet_sync_lineage"],
      disclosure_capsule_return: [
        "provider_return_locally_observed",
        "tool_return_locally_observed",
        "peer_return_signed",
      ],
    });
  });

  it("pins the external-reference vocabulary, five semantic triples, and raw signed bytes", () => {
    expect(DISCLOSURE_CAPSULE_RETURN_AUTHOR_AGENT_ID).toBe(
      "system:disclosure-capsule-return",
    );
    expect(MEMORY_EXTERNAL_DESTINATION_CLASSES).toEqual([
      "provider_inference",
      "external_tool",
      "peer_agent",
    ]);
    expect(MEMORY_EXTERNAL_EVIDENCE_BASES).toEqual([
      "local_tls_transport_observation",
      "destination_signature",
      "peer_signature",
    ]);
    expect(MEMORY_EXTERNAL_SOURCE_TRIPLES).toEqual([
      { source_class: "provider_return_locally_observed", destination_class: "provider_inference", evidence_basis: "local_tls_transport_observation" },
      { source_class: "provider_return_locally_observed", destination_class: "provider_inference", evidence_basis: "destination_signature" },
      { source_class: "tool_return_locally_observed", destination_class: "external_tool", evidence_basis: "local_tls_transport_observation" },
      { source_class: "tool_return_locally_observed", destination_class: "external_tool", evidence_basis: "destination_signature" },
      { source_class: "peer_return_signed", destination_class: "peer_agent", evidence_basis: "peer_signature" },
    ]);
    const body = {
      format: "SANCTUARY_SDW_MEMORY_ORIGIN_V1",
      origin_fortress_id: "fortress-origin",
      owner_ref: "owner-origin",
      passage_id: "passage-external",
      content_hash: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
      chunk_count: 1,
      author_agent_id: "system:disclosure-capsule-return",
      ingress_channel: "disclosure_capsule_return",
      source_class: "provider_return_locally_observed",
      external_source_ref: {
        format: "SANCTUARY_SDW_MEMORY_EXTERNAL_SOURCE_REF_V1",
        capsule_artifact_id: "dcap1_BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
        capsule_return_artifact_id: "dcret1_BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
        destination_class: "provider_inference",
        destination_id: "provider-local",
        evidence_basis: "local_tls_transport_observation",
        evidence_sha256: "06".repeat(32),
      },
      recorded_at: "2026-08-24T12:34:56Z",
      signer_identity_id: "origin-signer",
      signer_did: "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX",
      signature_scheme: "ed25519-v1",
    } as const satisfies MemoryOriginBody;
    expect(toBase64url(memoryOriginSigningBytes(body))).toBe(
      "c2FuY3R1YXJ5LnNkdy5tZW1vcnktb3JpZ2luLnYxCnsiYXV0aG9yX2FnZW50X2lkIjoic3lzdGVtOmRpc2Nsb3N1cmUtY2Fwc3VsZS1yZXR1cm4iLCJjaHVua19jb3VudCI6MSwiY29udGVudF9oYXNoIjoiQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TSIsImV4dGVybmFsX3NvdXJjZV9yZWYiOnsiY2Fwc3VsZV9hcnRpZmFjdF9pZCI6ImRjYXAxX0JBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVEiLCJjYXBzdWxlX3JldHVybl9hcnRpZmFjdF9pZCI6ImRjcmV0MV9CUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVIiwiZGVzdGluYXRpb25fY2xhc3MiOiJwcm92aWRlcl9pbmZlcmVuY2UiLCJkZXN0aW5hdGlvbl9pZCI6InByb3ZpZGVyLWxvY2FsIiwiZXZpZGVuY2VfYmFzaXMiOiJsb2NhbF90bHNfdHJhbnNwb3J0X29ic2VydmF0aW9uIiwiZXZpZGVuY2Vfc2hhMjU2IjoiMDYwNjA2MDYwNjA2MDYwNjA2MDYwNjA2MDYwNjA2MDYwNjA2MDYwNjA2MDYwNjA2MDYwNjA2MDYwNjA2MDYwNiIsImZvcm1hdCI6IlNBTkNUVUFSWV9TRFdfTUVNT1JZX0VYVEVSTkFMX1NPVVJDRV9SRUZfVjEifSwiZm9ybWF0IjoiU0FOQ1RVQVJZX1NEV19NRU1PUllfT1JJR0lOX1YxIiwiaW5ncmVzc19jaGFubmVsIjoiZGlzY2xvc3VyZV9jYXBzdWxlX3JldHVybiIsIm9yaWdpbl9mb3J0cmVzc19pZCI6ImZvcnRyZXNzLW9yaWdpbiIsIm93bmVyX3JlZiI6Im93bmVyLW9yaWdpbiIsInBhc3NhZ2VfaWQiOiJwYXNzYWdlLWV4dGVybmFsIiwicmVjb3JkZWRfYXQiOiIyMDI2LTA4LTI0VDEyOjM0OjU2WiIsInNpZ25hdHVyZV9zY2hlbWUiOiJlZDI1NTE5LXYxIiwic2lnbmVyX2RpZCI6ImRpZDprZXk6ejZNa29uM05lY2Q2TmtreWZvR29IeGlkMnpuR2M1OUxVM0s3bXViYVJjRmJMZkxYIiwic2lnbmVyX2lkZW50aXR5X2lkIjoib3JpZ2luLXNpZ25lciIsInNvdXJjZV9jbGFzcyI6InByb3ZpZGVyX3JldHVybl9sb2NhbGx5X29ic2VydmVkIn0",
    );
  });

  it("proves raw JSON memory_attest signing bytes cannot prefix-collide", () => {
    const rawJsonBytes = stringToBytes(JSON.stringify({ version: 1 }));
    expect(rawJsonBytes[0]).toBe("{".charCodeAt(0));
    expect(startsWithInternalSigningDomain(rawJsonBytes)).toBe(false);
    expect(readFileSync(memoryAttestSource, "utf8")).toContain(
      "const payloadBytes = stringToBytes(JSON.stringify(payload));",
    );
    for (const domain of [MEMORY_ORIGIN_SIGNING_DOMAIN, MEMORY_ADMISSION_SIGNING_DOMAIN]) {
      expect(rawJsonBytes.slice(0, stringToBytes(domain).length)).not.toEqual(stringToBytes(domain));
    }
  });
});
