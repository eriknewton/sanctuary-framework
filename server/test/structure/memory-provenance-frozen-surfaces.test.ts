import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  INTERNAL_SIGNING_DOMAIN_PREFIXES,
  MEMORY_ADMISSION_SIGNING_DOMAIN_PREFIX,
  MEMORY_ORIGIN_SIGNING_DOMAIN_PREFIX,
  startsWithInternalSigningDomain,
} from "../../src/core/signing-domains.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { MAX_KNOWN_SIGNERS } from "../../src/reputation/known-signers-store.js";
import {
  MAX_MEMORY_PROVENANCE_COMPANION_BYTES,
  MAX_MEMORY_PROVENANCE_SIGNER_ENTRIES,
  MEMORY_ADMISSION_CHANNELS,
  MEMORY_ADMISSION_FORMAT,
  MEMORY_ADMISSION_SIGNING_DOMAIN,
  MEMORY_ADMISSION_TRIPLES,
  MEMORY_INGRESS_CHANNELS,
  MEMORY_INGRESS_SOURCE_PAIRS,
  MEMORY_ORIGIN_FORMAT,
  MEMORY_ORIGIN_SIGNING_DOMAIN,
  MEMORY_ORIGIN_TRUST_TIERS,
  MEMORY_PROVENANCE_COMPANION_FORMAT,
  MEMORY_SIGNATURE_SCHEME,
  MEMORY_SOURCE_CLASSES,
  MEMORY_VERIFICATION_BASES,
} from "../../src/sdw/memory-provenance-contract.js";

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
      MEMORY_SIGNATURE_SCHEME,
    ]).toEqual([
      "SANCTUARY_SDW_MEMORY_PROVENANCE_V1",
      "SANCTUARY_SDW_MEMORY_ORIGIN_V1",
      "SANCTUARY_SDW_MEMORY_ADMISSION_V1",
      "ed25519-v1",
    ]);
    expect(MAX_MEMORY_PROVENANCE_COMPANION_BYTES).toBe(16 * 1024);
    expect(MAX_MEMORY_PROVENANCE_SIGNER_ENTRIES).toBe(MAX_KNOWN_SIGNERS);
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

  it("pins all ingress/source literals and the exact seven-row pair table", () => {
    expect(MEMORY_INGRESS_CHANNELS).toEqual([
      "memory_insert",
      "anthropic_memory_tool",
      "file_import",
      "memory_transcode",
      "legacy_migration",
      "legacy_unknown",
      "fleet_sync",
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
    ]);
    expect(MEMORY_INGRESS_SOURCE_PAIRS).toEqual({
      memory_insert: ["user_content", "agent_derived_clean", "system_generated"],
      anthropic_memory_tool: ["user_content", "agent_derived_clean", "system_generated"],
      file_import: ["claude_code_index", "claude_code_fact", "codex_index", "codex_summary", "codex_raw"],
      memory_transcode: ["transcode_manifest", "transcode_source_file", "exit_lineage"],
      legacy_migration: ["legacy_unattested"],
      legacy_unknown: ["legacy_unattested"],
      fleet_sync: ["fleet_sync_lineage"],
    });
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
