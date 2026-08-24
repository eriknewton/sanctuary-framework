import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import {
  legacyPublicKeyToDid,
  publicKeyToDid,
} from "../../src/core/identity.js";
import {
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import {
  MAX_MEMORY_PROVENANCE_COMPANION_BYTES,
  DISCLOSURE_CAPSULE_RETURN_AUTHOR_AGENT_ID,
  MEMORY_ADMISSION_CHANNELS,
  MEMORY_ADMISSION_SIGNING_DOMAIN,
  MEMORY_EXTERNAL_DESTINATION_CLASSES,
  MEMORY_EXTERNAL_EVIDENCE_BASES,
  MEMORY_INGRESS_CHANNELS,
  MEMORY_ORIGIN_SIGNING_DOMAIN,
  MEMORY_ORIGIN_TRUST_TIERS,
  MEMORY_SOURCE_CLASSES,
  MEMORY_VERIFICATION_BASES,
  computeMemoryOriginProvenanceDigest,
  createBoundedMemoryProvenanceSignerResolver,
  createMemoryProvenanceCompanion,
  isAllowedMemoryAdmissionTriple,
  isAllowedMemoryExternalSourceTriple,
  isAllowedMemoryIngressSourcePair,
  memoryAdmissionSigningBytes,
  memoryOriginSigningBytes,
  parseMemoryProvenanceCompanionJson,
  parseMemoryProvenanceCompanionValue,
  signMemoryAdmission,
  signMemoryOrigin,
  verifyMemoryProvenanceCompanion,
  type MemoryProvenanceCompanion,
  type MemoryProvenanceExpectedBinding,
  type MemoryProvenanceFailureCode,
  type MemoryProvenanceSigningHandle,
  type MemoryAdmissionInput,
  type MemoryOriginInput,
  type MemoryExternalSourceRefV1,
} from "../../src/sdw/memory-provenance-contract.js";

const ORIGIN_SEED = new Uint8Array(32).fill(1);
const ADMISSION_SEED = new Uint8Array(32).fill(2);
const ORIGIN_KEY = ed25519.getPublicKey(ORIGIN_SEED);
const ADMISSION_KEY = ed25519.getPublicKey(ADMISSION_SEED);

function signer(
  identityId: string,
  seed: Uint8Array,
): MemoryProvenanceSigningHandle {
  const publicKey = ed25519.getPublicKey(seed);
  return {
    identity_id: identityId,
    did: publicKeyToDid(publicKey),
    public_key: publicKey,
    sign: (bytes) => ed25519.sign(bytes, seed),
  };
}

const originSigner = signer("origin-signer", ORIGIN_SEED);
const admissionSigner = signer("admission-signer", ADMISSION_SEED);
const contentHash = toBase64url(new Uint8Array(32).fill(3));
const capsuleArtifactId = `dcap1_${toBase64url(new Uint8Array(32).fill(4))}` as const;
const capsuleReturnArtifactId = `dcret1_${toBase64url(new Uint8Array(32).fill(5))}` as const;

const EXPECTED_INGRESS_SOURCE_PAIRS = new Set([
  "memory_insert/user_content",
  "memory_insert/agent_derived_clean",
  "memory_insert/system_generated",
  "anthropic_memory_tool/user_content",
  "anthropic_memory_tool/agent_derived_clean",
  "anthropic_memory_tool/system_generated",
  "file_import/claude_code_index",
  "file_import/claude_code_fact",
  "file_import/codex_index",
  "file_import/codex_summary",
  "file_import/codex_raw",
  "memory_transcode/transcode_manifest",
  "memory_transcode/transcode_source_file",
  "memory_transcode/exit_lineage",
  "legacy_migration/legacy_unattested",
  "legacy_unknown/legacy_unattested",
  "fleet_sync/fleet_sync_lineage",
  "disclosure_capsule_return/provider_return_locally_observed",
  "disclosure_capsule_return/tool_return_locally_observed",
  "disclosure_capsule_return/peer_return_signed",
]);

const EXPECTED_EXTERNAL_SOURCE_TRIPLES = new Set([
  "provider_return_locally_observed/provider_inference/local_tls_transport_observation",
  "provider_return_locally_observed/provider_inference/destination_signature",
  "tool_return_locally_observed/external_tool/local_tls_transport_observation",
  "tool_return_locally_observed/external_tool/destination_signature",
  "peer_return_signed/peer_agent/peer_signature",
]);

const EXPECTED_ADMISSION_TRIPLES = new Set([
  "local_write/local_attested/local_primary_identity",
  "legacy_migration/legacy_unattested/legacy_local_observation",
  "exit_v2_import/foreign_direct/exit_v2_manifest_key",
  "exit_v2_import/foreign_relayed/exit_v2_known_signers",
  "exit_v2_import/legacy_unattested/exit_v2_legacy_v1",
  "fleet_sync/foreign_direct/fleet_sync_manifest_key",
  "fleet_sync/foreign_relayed/fleet_sync_known_signers",
  "operator_readmission/legacy_unattested/operator_readmission_after_compromise",
]);

type Mutable<T> = {
  -readonly [Key in keyof T]: T[Key] extends object ? Mutable<T[Key]> : T[Key];
};
type MutableCompanion = Mutable<MemoryProvenanceCompanion>;

const expected: MemoryProvenanceExpectedBinding = {
  origin: {
    origin_fortress_id: "fortress-origin",
    owner_ref: "owner-origin",
    passage_id: "passage-001",
    content_hash: contentHash,
    chunk_count: 2,
  },
  destination: {
    destination_fortress_id: "fortress-destination",
    destination_owner_ref: "owner-destination",
    passage_id: "passage-001",
  },
};

function requireOk<T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T {
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error("expected successful result");
  return result.value;
}

function buildCompanion(): MemoryProvenanceCompanion {
  const origin = requireOk(
    signMemoryOrigin(
      {
        ...expected.origin,
        author_agent_id: "agent-claude",
        ingress_channel: "memory_insert",
        source_class: "user_content",
        recorded_at: "2026-08-24T12:34:56.789-06:00",
      },
      originSigner,
    ),
  );
  return requireOk(
    createMemoryProvenanceCompanion(
      origin,
      {
        ...expected.destination,
        admission_channel: "local_write",
        origin_trust_tier: "local_attested",
        verification_basis: "local_primary_identity",
        admitted_at: "2026-08-24T12:35:01.123-06:00",
      },
      admissionSigner,
    ),
  );
}

function externalRef(
  destination_class: "provider_inference" | "external_tool" | "peer_agent",
  evidence_basis:
    | "local_tls_transport_observation"
    | "destination_signature"
    | "peer_signature",
): MemoryExternalSourceRefV1 {
  return {
    format: "SANCTUARY_SDW_MEMORY_EXTERNAL_SOURCE_REF_V1",
    capsule_artifact_id: capsuleArtifactId,
    capsule_return_artifact_id: capsuleReturnArtifactId,
    destination_class,
    destination_id: "destination-001",
    evidence_basis,
    ...(evidence_basis === "local_tls_transport_observation"
      ? {}
      : { remote_signer_did: originSigner.did }),
    evidence_sha256: "06".repeat(32),
  } as MemoryExternalSourceRefV1;
}

function validExternalInput(
  source_class:
    | "provider_return_locally_observed"
    | "tool_return_locally_observed"
    | "peer_return_signed",
): MemoryOriginInput {
  const destination = source_class === "provider_return_locally_observed"
    ? "provider_inference"
    : source_class === "tool_return_locally_observed"
      ? "external_tool"
      : "peer_agent";
  const basis = source_class === "peer_return_signed"
    ? "peer_signature"
    : "local_tls_transport_observation";
  return {
    ...expected.origin,
    author_agent_id: DISCLOSURE_CAPSULE_RETURN_AUTHOR_AGENT_ID,
    ingress_channel: "disclosure_capsule_return",
    source_class,
    external_source_ref: externalRef(destination, basis),
    recorded_at: "2026-08-24T12:34:56Z",
  } as MemoryOriginInput;
}

function resolverForFixture() {
  return requireOk(
    createBoundedMemoryProvenanceSignerResolver([
      {
        signer_identity_id: originSigner.identity_id,
        signer_did: originSigner.did,
        public_key: toBase64url(ORIGIN_KEY),
      },
      {
        signer_identity_id: admissionSigner.identity_id,
        signer_did: admissionSigner.did,
        public_key: toBase64url(ADMISSION_KEY),
      },
    ]),
  );
}

function clone(value: MemoryProvenanceCompanion): MutableCompanion {
  return structuredClone(value) as MutableCompanion;
}

function expectFailure(
  result: { ok: boolean; error?: { code: MemoryProvenanceFailureCode } },
  code: MemoryProvenanceFailureCode,
): void {
  expect(result.ok).toBe(false);
  expect(result.error?.code).toBe(code);
}

describe("C1 memory-provenance canonical contract", () => {
  it("matches the frozen deterministic vector byte-for-byte", () => {
    const fixturePath = fileURLToPath(
      new URL("../fixtures/memory-provenance-v1.json", import.meta.url),
    );
    const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
      companion: MemoryProvenanceCompanion;
      origin_public_key: string;
      admission_public_key: string;
      origin_signing_bytes_base64url: string;
      admission_signing_bytes_base64url: string;
    };
    const companion = buildCompanion();
    expect(companion).toEqual(fixture.companion);
    expect(toBase64url(memoryOriginSigningBytes(companion.origin.body))).toBe(
      fixture.origin_signing_bytes_base64url,
    );
    expect(toBase64url(memoryAdmissionSigningBytes(companion.admission.body))).toBe(
      fixture.admission_signing_bytes_base64url,
    );
    expect(toBase64url(ORIGIN_KEY)).toBe(fixture.origin_public_key);
    expect(toBase64url(ADMISSION_KEY)).toBe(fixture.admission_public_key);
    expect(companion.origin.body.content_hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(companion.origin_provenance_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(computeMemoryOriginProvenanceDigest(companion.origin)).toBe(
      companion.origin_provenance_digest,
    );
    expect(
      Array.from(
        hash(canonicalizeToBytes({
          body: companion.origin.body,
          signature: companion.origin.signature,
        })),
        (byte) => byte.toString(16).padStart(2, "0"),
      ).join(""),
    ).toBe(companion.origin_provenance_digest);
    expect(verifyMemoryProvenanceCompanion(companion, resolverForFixture(), expected).ok).toBe(true);
    const relocated = requireOk(createMemoryProvenanceCompanion(
      companion.origin,
      {
        ...expected.destination,
        passage_id: "passage-destination",
        admission_channel: "local_write",
        origin_trust_tier: "local_attested",
        verification_basis: "local_primary_identity",
        admitted_at: "2026-08-24T12:36:00Z",
      },
      admissionSigner,
    ));
    expect(relocated.origin.body.passage_id).toBe("passage-001");
    expect(verifyMemoryProvenanceCompanion(
      relocated,
      resolverForFixture(),
      {
        ...expected,
        destination: { ...expected.destination, passage_id: "passage-destination" },
      },
    ).ok).toBe(true);
  });

  it("uses exact newline-terminated domains and rejects wrong domain or delimiter signatures", () => {
    expect(MEMORY_ORIGIN_SIGNING_DOMAIN).toBe("sanctuary.sdw.memory-origin.v1\n");
    expect(MEMORY_ADMISSION_SIGNING_DOMAIN).toBe("sanctuary.sdw.memory-admission.v1\n");
    const companion = buildCompanion();
    for (const prefix of [
      "sanctuary.sdw.memory-origin.v1",
      "sanctuary.sdw.memory-origin.v1\0",
      "sanctuary.sdw.memory-admission.v1\n",
    ]) {
      const mutated = clone(companion);
      mutated.origin.signature = toBase64url(
        ed25519.sign(
          new Uint8Array([
            ...stringToBytes(prefix),
            ...memoryOriginSigningBytes(mutated.origin.body).slice(
              stringToBytes(MEMORY_ORIGIN_SIGNING_DOMAIN).length,
            ),
          ]),
          ORIGIN_SEED,
        ),
      );
      expectFailure(
        verifyMemoryProvenanceCompanion(mutated, resolverForFixture(), expected),
        "signature_invalid",
      );
    }
    for (const prefix of [
      "sanctuary.sdw.memory-admission.v1",
      "sanctuary.sdw.memory-admission.v1\0",
      "sanctuary.sdw.memory-origin.v1\n",
    ]) {
      const mutated = clone(companion);
      mutated.admission.signature = toBase64url(
        ed25519.sign(
          new Uint8Array([
            ...stringToBytes(prefix),
            ...memoryAdmissionSigningBytes(mutated.admission.body).slice(
              stringToBytes(MEMORY_ADMISSION_SIGNING_DOMAIN).length,
            ),
          ]),
          ADMISSION_SEED,
        ),
      );
      expectFailure(
        verifyMemoryProvenanceCompanion(mutated, resolverForFixture(), expected),
        "signature_invalid",
      );
    }
  });

  it("enumerates every allowed and forbidden ingress/source pair", () => {
    let observedAllowed = 0;
    for (const channel of MEMORY_INGRESS_CHANNELS) {
      for (const source of MEMORY_SOURCE_CLASSES) {
        const actual = isAllowedMemoryIngressSourcePair(channel, source);
        expect(actual, `${channel}/${source}`).toBe(
          EXPECTED_INGRESS_SOURCE_PAIRS.has(`${channel}/${source}`),
        );
        const isValidExternalPair =
          channel === "disclosure_capsule_return" &&
          (source === "provider_return_locally_observed" ||
            source === "tool_return_locally_observed" ||
            source === "peer_return_signed");
        const candidate = isValidExternalPair
          ? validExternalInput(source)
          : {
              ...expected.origin,
              author_agent_id: "agent-claude",
              ingress_channel: channel,
              source_class: source,
              recorded_at: "2026-08-24T12:34:56Z",
            } as MemoryOriginInput;
        const constructed = signMemoryOrigin(candidate, originSigner);
        expect(constructed.ok, `constructor ${channel}/${source}`).toBe(actual);
        if (!actual && !constructed.ok) {
          expect(constructed.error.code).toBe("ingress_source_pair_invalid");
        }
        if (actual) observedAllowed += 1;
      }
    }
    expect(observedAllowed).toBe(20);
  });

  it("exhaustively enforces external source/destination/evidence triples", () => {
    const sources = [
      "provider_return_locally_observed",
      "tool_return_locally_observed",
      "peer_return_signed",
    ] as const;
    let observedAllowed = 0;
    for (const source_class of sources) {
      for (const destination_class of MEMORY_EXTERNAL_DESTINATION_CLASSES) {
        for (const evidence_basis of MEMORY_EXTERNAL_EVIDENCE_BASES) {
          const label = `${source_class}/${destination_class}/${evidence_basis}`;
          const actual = isAllowedMemoryExternalSourceTriple({
            source_class,
            destination_class,
            evidence_basis,
          });
          expect(actual, label).toBe(EXPECTED_EXTERNAL_SOURCE_TRIPLES.has(label));
          const candidate = {
            ...expected.origin,
            author_agent_id: DISCLOSURE_CAPSULE_RETURN_AUTHOR_AGENT_ID,
            ingress_channel: "disclosure_capsule_return",
            source_class,
            external_source_ref: externalRef(destination_class, evidence_basis),
            recorded_at: "2026-08-24T12:34:56Z",
          } as unknown as MemoryOriginInput;
          const constructed = signMemoryOrigin(candidate, originSigner);
          expect(constructed.ok, label).toBe(actual);
          if (!actual && !constructed.ok) {
            expect(constructed.error.code).toBe("external_source_ref_invalid");
          }
          if (actual) observedAllowed += 1;
        }
      }
    }
    expect(observedAllowed).toBe(5);
  });

  it("requires exact external-reference keys and the code-owned return author", () => {
    const provider = validExternalInput("provider_return_locally_observed");
    expect(signMemoryOrigin(provider, originSigner).ok).toBe(true);
    expectFailure(
      signMemoryOrigin(
        { ...provider, author_agent_id: "provider-name" } as unknown as MemoryOriginInput,
        originSigner,
      ),
      "external_source_ref_invalid",
    );
    const missingRef = { ...provider } as unknown as Record<string, unknown>;
    delete missingRef.external_source_ref;
    expectFailure(
      signMemoryOrigin(missingRef as unknown as MemoryOriginInput, originSigner),
      "external_source_ref_invalid",
    );
    const extraRef = {
      ...provider,
      external_source_ref: {
        ...provider.external_source_ref,
        caller_claimed_safe: true,
      },
    };
    expectFailure(
      signMemoryOrigin(extraRef as unknown as MemoryOriginInput, originSigner),
      "unknown_key",
    );
    const existingWithRef = {
      ...expected.origin,
      author_agent_id: "agent-claude",
      ingress_channel: "memory_insert",
      source_class: "user_content",
      external_source_ref: provider.external_source_ref,
      recorded_at: "2026-08-24T12:34:56Z",
    };
    expectFailure(
      signMemoryOrigin(existingWithRef as unknown as MemoryOriginInput, originSigner),
      "external_source_ref_invalid",
    );
    for (const external_source_ref of [
      { ...provider.external_source_ref, capsule_artifact_id: "dcap1_short" },
      { ...provider.external_source_ref, capsule_return_artifact_id: `${capsuleReturnArtifactId}=` },
      { ...provider.external_source_ref, evidence_sha256: "AB".repeat(32) },
      { ...provider.external_source_ref, destination_id: "unsafe destination" },
    ]) {
      expect(
        signMemoryOrigin(
          { ...provider, external_source_ref } as unknown as MemoryOriginInput,
          originSigner,
        ).ok,
      ).toBe(false);
    }
    const signed = requireOk(signMemoryOrigin(provider, originSigner));
    const companion = requireOk(createMemoryProvenanceCompanion(
      signed,
      {
        ...expected.destination,
        admission_channel: "local_write",
        origin_trust_tier: "local_attested",
        verification_basis: "local_primary_identity",
        admitted_at: "2026-08-24T12:35:01Z",
      },
      admissionSigner,
    ));
    const duplicateNestedJson = JSON.stringify(companion).replace(
      `"destination_id":"destination-001"`,
      `"destination_id":"destination-001","destination_id":"swapped"`,
    );
    expectFailure(parseMemoryProvenanceCompanionJson(duplicateNestedJson), "duplicate_key");
  });

  it("enforces signature-evidence signer presence and local-observation signer absence", () => {
    const provider = validExternalInput("provider_return_locally_observed");
    const observedWithSigner = {
      ...provider,
      external_source_ref: {
        ...provider.external_source_ref,
        remote_signer_did: originSigner.did,
      },
    };
    expectFailure(
      signMemoryOrigin(observedWithSigner as unknown as MemoryOriginInput, originSigner),
      "external_source_ref_invalid",
    );
    const signed = {
      ...provider,
      external_source_ref: {
        ...externalRef("provider_inference", "destination_signature"),
        remote_signer_did: "did:web:provider.example",
      },
    };
    const signedWithoutDid = structuredClone(signed) as unknown as {
      external_source_ref: Record<string, unknown>;
    };
    delete signedWithoutDid.external_source_ref.remote_signer_did;
    expectFailure(
      signMemoryOrigin(signedWithoutDid as unknown as MemoryOriginInput, originSigner),
      "external_source_ref_invalid",
    );
    expect(signMemoryOrigin(signed as MemoryOriginInput, originSigner).ok).toBe(true);
  });

  it("binds every external-reference field under the existing origin domain", () => {
    const origin = requireOk(
      signMemoryOrigin(validExternalInput("peer_return_signed"), originSigner),
    );
    const companion = requireOk(
      createMemoryProvenanceCompanion(
        origin,
        {
          ...expected.destination,
          admission_channel: "local_write",
          origin_trust_tier: "local_attested",
          verification_basis: "local_primary_identity",
          admitted_at: "2026-08-24T12:35:01Z",
        },
        admissionSigner,
      ),
    );
    expect(verifyMemoryProvenanceCompanion(companion, resolverForFixture(), expected).ok).toBe(true);
    const mutated = structuredClone(companion) as unknown as {
      origin: { body: { external_source_ref: { destination_id: string } } };
    };
    mutated.origin.body.external_source_ref.destination_id = "peer-swapped";
    expectFailure(
      verifyMemoryProvenanceCompanion(mutated, resolverForFixture(), expected),
      "signature_invalid",
    );
  });

  it("enumerates every allowed and forbidden admission triple", () => {
    let observedAllowed = 0;
    for (const admission_channel of MEMORY_ADMISSION_CHANNELS) {
      for (const origin_trust_tier of MEMORY_ORIGIN_TRUST_TIERS) {
        for (const verification_basis of MEMORY_VERIFICATION_BASES) {
          const label = `${admission_channel}/${origin_trust_tier}/${verification_basis}`;
          const actual = isAllowedMemoryAdmissionTriple({
            admission_channel,
            origin_trust_tier,
            verification_basis,
          });
          expect(actual, label).toBe(EXPECTED_ADMISSION_TRIPLES.has(label));
          const constructed = signMemoryAdmission(
            {
              origin_provenance_digest: "04".repeat(32),
              ...expected.destination,
              admission_channel,
              origin_trust_tier,
              verification_basis,
              admitted_at: "2026-08-24T12:35:01Z",
              ...(admission_channel === "exit_v2_import" || admission_channel === "fleet_sync"
                ? { transfer_lineage_ref: "transfer-001" }
                : {}),
            },
            admissionSigner,
          );
          expect(constructed.ok, `constructor ${label}`).toBe(actual);
          if (!actual && !constructed.ok) {
            expect(constructed.error.code).toBe("admission_triple_invalid");
          }
          if (actual) observedAllowed += 1;
        }
      }
    }
    expect(observedAllowed).toBe(8);
  });

  it("rejects unknown/missing keys and every unknown enum literal", () => {
    const base = buildCompanion();
    expectFailure(parseMemoryProvenanceCompanionValue(null), "object_expected");
    expectFailure(parseMemoryProvenanceCompanionValue([]), "object_expected");
    const extra = structuredClone(base) as unknown as Record<string, unknown>;
    extra.unexpected = true;
    expectFailure(parseMemoryProvenanceCompanionValue(extra), "unknown_key");
    const missing = structuredClone(base) as unknown as { admission: { body: Record<string, unknown> } };
    delete missing.admission.body.admitted_at;
    expectFailure(parseMemoryProvenanceCompanionValue(missing), "missing_key");
    const nestedExtra = clone(base) as unknown as { origin: { body: Record<string, unknown> } };
    nestedExtra.origin.body.unexpected = true;
    expectFailure(parseMemoryProvenanceCompanionValue(nestedExtra), "unknown_key");
    const missingOrigin = clone(base) as unknown as Record<string, unknown>;
    delete missingOrigin.origin;
    expectFailure(parseMemoryProvenanceCompanionValue(missingOrigin), "missing_key");
    const duplicateJson = JSON.stringify(base).replace(
      `"format":"${base.format}"`,
      `"format":"${base.format}","\\u0066ormat":"${base.format}"`,
    );
    expectFailure(parseMemoryProvenanceCompanionJson(duplicateJson), "duplicate_key");
    for (const mutate of [
      (value: MutableCompanion) => { value.format = "unsupported" as typeof value.format; },
      (value: MutableCompanion) => { value.origin.body.format = "unsupported" as typeof value.origin.body.format; },
      (value: MutableCompanion) => { value.admission.body.format = "unsupported" as typeof value.admission.body.format; },
      (value: MutableCompanion) => { value.origin.body.signature_scheme = "unsupported" as typeof value.origin.body.signature_scheme; },
      (value: MutableCompanion) => { value.admission.body.signature_scheme = "unsupported" as typeof value.admission.body.signature_scheme; },
    ]) {
      const mutated = clone(base);
      mutate(mutated);
      expectFailure(parseMemoryProvenanceCompanionValue(mutated), "invalid_literal");
    }
    for (const [path, value] of [
      ["ingress_channel", "unknown_ingress"],
      ["source_class", "unknown_source"],
    ] as const) {
      const mutated = clone(base) as unknown as { origin: { body: Record<string, unknown> } };
      mutated.origin.body[path] = value;
      expectFailure(parseMemoryProvenanceCompanionValue(mutated), "invalid_literal");
      const candidate = {
        ...expected.origin,
        author_agent_id: "agent-claude",
        ingress_channel: path === "ingress_channel" ? value : "memory_insert",
        source_class: path === "source_class" ? value : "user_content",
        recorded_at: "2026-08-24T12:34:56Z",
      } as unknown as MemoryOriginInput;
      expectFailure(signMemoryOrigin(candidate, originSigner), "invalid_literal");
    }
    for (const [path, value] of [
      ["admission_channel", "unknown_admission"],
      ["origin_trust_tier", "unknown_trust"],
      ["verification_basis", "unknown_basis"],
    ] as const) {
      const mutated = clone(base) as unknown as { admission: { body: Record<string, unknown> } };
      mutated.admission.body[path] = value;
      expectFailure(parseMemoryProvenanceCompanionValue(mutated), "invalid_literal");
      const candidate = {
        origin_provenance_digest: "04".repeat(32),
        ...expected.destination,
        admission_channel: path === "admission_channel" ? value : "local_write",
        origin_trust_tier: path === "origin_trust_tier" ? value : "local_attested",
        verification_basis: path === "verification_basis" ? value : "local_primary_identity",
        admitted_at: "2026-08-24T12:35:01Z",
      } as unknown as MemoryAdmissionInput;
      expectFailure(signMemoryAdmission(candidate, admissionSigner), "invalid_literal");
    }
  });

  it("rejects invalid allowed-table combinations and lineage mismatches", () => {
    const base = buildCompanion();
    const badPair = clone(base);
    badPair.origin.body.source_class = "codex_raw";
    expectFailure(parseMemoryProvenanceCompanionValue(badPair), "ingress_source_pair_invalid");
    const badTriple = clone(base);
    badTriple.admission.body.origin_trust_tier = "foreign_direct";
    expectFailure(parseMemoryProvenanceCompanionValue(badTriple), "admission_triple_invalid");
    const strayLineage = clone(base);
    strayLineage.admission.body.transfer_lineage_ref = "exit-001";
    expectFailure(parseMemoryProvenanceCompanionValue(strayLineage), "transfer_lineage_invalid");

    const exitBody = clone(base).admission.body;
    exitBody.admission_channel = "exit_v2_import";
    exitBody.origin_trust_tier = "foreign_direct";
    exitBody.verification_basis = "exit_v2_manifest_key";
    expectFailure(
      parseMemoryProvenanceCompanionValue({
        ...base,
        admission: { body: exitBody, signature: base.admission.signature },
      }),
      "transfer_lineage_invalid",
    );
  });

  it("rejects wrong lengths, malformed base64url, timestamps, and identifiers", () => {
    const mutations: Array<[
      (value: MutableCompanion) => void,
      MemoryProvenanceFailureCode,
    ]> = [
      [(value) => { value.origin.signature = toBase64url(new Uint8Array(63)); }, "invalid_signature_length"],
      [(value) => { value.admission.signature = "abc="; }, "invalid_base64url"],
      [(value) => { value.origin.body.content_hash = toBase64url(new Uint8Array(31)); }, "invalid_hash"],
      [(value) => { value.origin.body.content_hash = "abc="; }, "invalid_base64url"],
      [(value) => { value.origin.body.content_hash = `${contentHash.slice(0, -1)}N`; }, "invalid_base64url"],
      [(value) => { value.origin_provenance_digest = "AB".repeat(32); }, "invalid_hash"],
      [(value) => { value.admission.body.origin_provenance_digest = "0".repeat(63); }, "invalid_hash"],
      [(value) => { value.origin.body.recorded_at = "2026-02-30T00:00:00Z"; }, "invalid_timestamp"],
      [(value) => { value.admission.body.admitted_at = "2026-08-24 12:00:00"; }, "invalid_timestamp"],
      [(value) => { value.origin.body.owner_ref = "contains a space"; }, "invalid_identifier"],
      [(value) => { value.origin.body.owner_ref = "x".repeat(257); }, "invalid_identifier"],
      [(value) => { value.origin.body.signer_did = "did:key:"; }, "invalid_identifier"],
      [(value) => { value.origin.body.chunk_count = 0; }, "invalid_count"],
      [(value) => { value.origin.body.chunk_count = -1; }, "invalid_count"],
      [(value) => { value.origin.body.chunk_count = Number.MAX_SAFE_INTEGER + 1; }, "invalid_count"],
    ];
    for (const [mutate, code] of mutations) {
      const value = buildCompanion();
      mutate(value);
      expectFailure(parseMemoryProvenanceCompanionValue(value), code);
    }

    const badKey = createBoundedMemoryProvenanceSignerResolver([
      {
        signer_identity_id: "short-key",
        signer_did: publicKeyToDid(ORIGIN_KEY),
        public_key: toBase64url(new Uint8Array(31)),
      },
    ]);
    expectFailure(badKey, "invalid_public_key_length");
    expectFailure(
      createBoundedMemoryProvenanceSignerResolver([{
        signer_identity_id: "bad-key",
        signer_did: publicKeyToDid(ORIGIN_KEY),
        public_key: "abc=",
      }]),
      "invalid_base64url",
    );
  });

  it("bounds companion bytes before parsing JSON", () => {
    const oversized = `{"${"x".repeat(MAX_MEMORY_PROVENANCE_COMPANION_BYTES)}":0}`;
    expectFailure(parseMemoryProvenanceCompanionJson(oversized), "companion_too_large");
    expectFailure(parseMemoryProvenanceCompanionJson("{"), "json_trailing_bytes");
    expectFailure(
      parseMemoryProvenanceCompanionJson(new Uint8Array([0xff, 0xfe])),
      "json_invalid",
    );
    expectFailure(
      parseMemoryProvenanceCompanionJson('{"__proto__":{}}'),
      "prototype_key",
    );
    expectFailure(
      parseMemoryProvenanceCompanionJson(`${"[".repeat(40)}1${"]".repeat(40)}`),
      "json_too_deep",
    );
    expectFailure(
      parseMemoryProvenanceCompanionJson(`${JSON.stringify(buildCompanion())} trailing`),
      "json_trailing_bytes",
    );
  });
});

describe("C1 memory-provenance verification and signer resolution", () => {
  it("rejects origin subject, content, and destination mismatches", () => {
    const companion = buildCompanion();
    for (const altered of [
      { ...expected, origin: { ...expected.origin, passage_id: "passage-other" } },
      { ...expected, origin: { ...expected.origin, content_hash: toBase64url(new Uint8Array(32).fill(9)) } },
      { ...expected, destination: { ...expected.destination, destination_owner_ref: "owner-other" } },
    ]) {
      const result = verifyMemoryProvenanceCompanion(companion, resolverForFixture(), altered);
      expectFailure(
        result,
        altered.destination.destination_owner_ref === "owner-other"
          ? "destination_mismatch"
          : "origin_subject_mismatch",
      );
    }
  });

  it("rejects signature and provenance-digest mutations", () => {
    const signatureMutation = clone(buildCompanion());
    signatureMutation.origin.signature = toBase64url(new Uint8Array(64).fill(7));
    expectFailure(
      verifyMemoryProvenanceCompanion(signatureMutation, resolverForFixture(), expected),
      "signature_invalid",
    );
    const digestMutation = clone(buildCompanion());
    digestMutation.origin_provenance_digest = "08".repeat(32);
    expectFailure(
      verifyMemoryProvenanceCompanion(digestMutation, resolverForFixture(), expected),
      "origin_provenance_digest_mismatch",
    );
  });

  it("rejects DID/key mismatch, duplicate conflict, self-entry, and unknown signer", () => {
    expectFailure(
      createBoundedMemoryProvenanceSignerResolver([
        {
          signer_identity_id: "origin-signer",
          signer_did: publicKeyToDid(ADMISSION_KEY),
          public_key: toBase64url(ORIGIN_KEY),
        },
      ]),
      "signer_did_key_mismatch",
    );
    expectFailure(
      createBoundedMemoryProvenanceSignerResolver([
        {
          signer_identity_id: "origin-signer",
          signer_did: publicKeyToDid(ORIGIN_KEY),
          public_key: toBase64url(ORIGIN_KEY),
        },
        {
          signer_identity_id: "different-identity",
          signer_did: publicKeyToDid(ORIGIN_KEY),
          public_key: toBase64url(ORIGIN_KEY),
        },
      ]),
      "signer_duplicate_conflict",
    );
    expectFailure(
      createBoundedMemoryProvenanceSignerResolver([
        {
          signer_identity_id: "same-identity",
          signer_did: publicKeyToDid(ORIGIN_KEY),
          public_key: toBase64url(ORIGIN_KEY),
        },
        {
          signer_identity_id: "same-identity",
          signer_did: publicKeyToDid(ADMISSION_KEY),
          public_key: toBase64url(ADMISSION_KEY),
        },
      ]),
      "signer_duplicate_conflict",
    );
    expectFailure(
      createBoundedMemoryProvenanceSignerResolver(
        [{
          signer_identity_id: "origin-signer",
          signer_did: publicKeyToDid(ORIGIN_KEY),
          public_key: toBase64url(ORIGIN_KEY),
        }],
        { forbiddenSigner: { did: legacyPublicKeyToDid(ORIGIN_KEY), public_key: ORIGIN_KEY } },
      ),
      "signer_self_entry",
    );
    const empty = requireOk(createBoundedMemoryProvenanceSignerResolver([]));
    expectFailure(
      verifyMemoryProvenanceCompanion(buildCompanion(), empty, expected),
      "signer_unknown",
    );
    const originOnly = requireOk(createBoundedMemoryProvenanceSignerResolver([{
      signer_identity_id: originSigner.identity_id,
      signer_did: originSigner.did,
      public_key: toBase64url(ORIGIN_KEY),
    }]));
    expectFailure(
      verifyMemoryProvenanceCompanion(buildCompanion(), originOnly, expected),
      "signer_unknown",
    );
  });

  it("checks the signer-table bound before inspecting attacker elements", () => {
    let touched = false;
    const attacker = Object.defineProperty({}, "signer_identity_id", {
      enumerable: true,
      get() {
        touched = true;
        throw new Error("must not inspect");
      },
    });
    expectFailure(
      createBoundedMemoryProvenanceSignerResolver([attacker], { maxEntries: 0 }),
      "signer_table_too_large",
    );
    expect(touched).toBe(false);
    expectFailure(
      createBoundedMemoryProvenanceSignerResolver(
        null as unknown as readonly unknown[],
      ),
      "object_expected",
    );
  });

  it("self-verifies narrow signing handles and refuses invalid signer output", () => {
    const badLength = { ...originSigner, sign: () => new Uint8Array(63) };
    expectFailure(
      signMemoryOrigin(
        {
          ...expected.origin,
          author_agent_id: "agent-claude",
          ingress_channel: "memory_insert",
          source_class: "user_content",
          recorded_at: "2026-08-24T12:34:56Z",
        },
        badLength,
      ),
      "invalid_signature_length",
    );
    const wrongSignature = { ...originSigner, sign: () => new Uint8Array(64) };
    expectFailure(
      signMemoryOrigin(
        {
          ...expected.origin,
          author_agent_id: "agent-claude",
          ingress_channel: "memory_insert",
          source_class: "user_content",
          recorded_at: "2026-08-24T12:34:56Z",
        },
        wrongSignature,
      ),
      "signature_invalid",
    );
    const throwingSigner = {
      ...originSigner,
      sign: () => { throw new Error("unavailable signer"); },
    };
    expectFailure(
      signMemoryOrigin(
        {
          ...expected.origin,
          author_agent_id: "agent-claude",
          ingress_channel: "memory_insert",
          source_class: "user_content",
          recorded_at: "2026-08-24T12:34:56Z",
        },
        throwingSigner,
      ),
      "sign_failed",
    );
  });
});
