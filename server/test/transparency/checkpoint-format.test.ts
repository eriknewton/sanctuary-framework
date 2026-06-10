import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import {
  TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX,
  checkpointPayloadOf,
  checkpointSigningBytes,
  computeCheckpointHash,
  isEnforcementCheckpointRecord,
  isTransparencyBundle,
  transparencyRuleLabel,
  verifyEnforcementCheckpointSignature,
  type EnforcementCheckpointPayload,
  type EnforcementCheckpointRecord,
} from "../../src/transparency/checkpoint.js";
import { bytesToString, toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";

function samplePayload(
  overrides: Partial<EnforcementCheckpointPayload> = {}
): EnforcementCheckpointPayload {
  return {
    checkpoint_kind: "enforcement-checkpoint",
    schema_version: 1,
    counter: 1,
    previous_checkpoint_hash: "GENESIS",
    issued_at: "2026-06-09T00:00:00.000Z",
    fortress_id: "fortress-test",
    audit: {
      merkle_root: "a".repeat(64),
      lowest_sequence: 1,
      highest_sequence: 5,
      head_hash: "b".repeat(64),
      entry_count: 5,
    },
    policy: {
      rules_sha256: "c".repeat(64),
      rules_count: 2,
      manifest_sha256: null,
    },
    daemon: { version: "1.3.3", binary_sha256: "d".repeat(64) },
    enforcement: {
      total_allowed: 3,
      total_blocked: 2,
      rules: [{ rule_label: "e".repeat(64), allowed: 3, blocked: 2 }],
    },
    ...overrides,
  };
}

function signRecord(
  payload: EnforcementCheckpointPayload,
  privateKey: Uint8Array
): EnforcementCheckpointRecord {
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    ...payload,
    signer_kid: `castle-wall:${toBase64url(publicKey)}`,
    signature: toBase64url(ed25519.sign(checkpointSigningBytes(payload), privateKey)),
    signature_algorithm: "Ed25519",
    payload_encoding: "domain-separated-canonical-json-v1",
    public_key: toBase64url(publicKey),
  };
}

describe("transparency checkpoint format", () => {
  it("signing bytes are domain-separated and canonical (key order independent)", () => {
    const payload = samplePayload();
    const bytes = bytesToString(checkpointSigningBytes(payload));
    expect(bytes.startsWith(TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX)).toBe(true);
    // Same logical payload with different property insertion order signs identically.
    const reordered = Object.fromEntries(
      Object.entries(payload).reverse()
    ) as unknown as EnforcementCheckpointPayload;
    expect(bytesToString(checkpointSigningBytes(reordered))).toBe(bytes);
  });

  it("checkpoint hash changes when ANY signed field changes", () => {
    const base = computeCheckpointHash(samplePayload());
    expect(computeCheckpointHash(samplePayload({ counter: 2 }))).not.toBe(base);
    expect(
      computeCheckpointHash(
        samplePayload({
          enforcement: { total_allowed: 4, total_blocked: 2, rules: [] },
        })
      )
    ).not.toBe(base);
    expect(
      computeCheckpointHash(
        samplePayload({
          daemon: { version: "1.3.3", binary_sha256: "f".repeat(64) },
        })
      )
    ).not.toBe(base);
  });

  it("rule labels are deterministic, fortress-scoped, and opaque", () => {
    const a = transparencyRuleLabel("fortress-1", "allow-github");
    expect(transparencyRuleLabel("fortress-1", "allow-github")).toBe(a);
    expect(transparencyRuleLabel("fortress-2", "allow-github")).not.toBe(a);
    expect(transparencyRuleLabel("fortress-1", "allow-gitlab")).not.toBe(a);
    // Opaque: a 64-hex digest, not the rule id (constraint #7).
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toContain("github");
  });

  it("signature verifies against the correct key and ONLY that key", () => {
    const privateKey = randomBytes(32);
    const record = signRecord(samplePayload(), privateKey);
    expect(
      verifyEnforcementCheckpointSignature(record, ed25519.getPublicKey(privateKey))
    ).toBe(true);
    expect(
      verifyEnforcementCheckpointSignature(record, ed25519.getPublicKey(randomBytes(32)))
    ).toBe(false);
    // Tampering with a signed field (the counters) invalidates the signature.
    const tampered = {
      ...record,
      enforcement: { ...record.enforcement, total_blocked: 0 },
    };
    expect(
      verifyEnforcementCheckpointSignature(tampered, ed25519.getPublicKey(privateKey))
    ).toBe(false);
  });

  it("type guard accepts a signed record and rejects mutations", () => {
    const record = signRecord(samplePayload(), randomBytes(32));
    expect(isEnforcementCheckpointRecord(record)).toBe(true);
    expect(isEnforcementCheckpointRecord({ ...record, counter: 0 })).toBe(false);
    expect(isEnforcementCheckpointRecord({ ...record, signature: null })).toBe(false);
    expect(
      isEnforcementCheckpointRecord({ ...record, previous_checkpoint_hash: "zz" })
    ).toBe(false);
    expect(
      isEnforcementCheckpointRecord({
        ...record,
        audit: { ...record.audit, merkle_root: "not-hex" },
      })
    ).toBe(false);
    // There is NO unsigned variant of this record.
    const { signature: _omitted, ...withoutSignature } = record;
    expect(isEnforcementCheckpointRecord(withoutSignature)).toBe(false);
  });

  it("bundle guard requires format, key, and well-formed checkpoints", () => {
    const record = signRecord(samplePayload(), randomBytes(32));
    const bundle = {
      format: "SANCTUARY_TRANSPARENCY_BUNDLE_V1",
      exported_at: "2026-06-09T00:00:00.000Z",
      public_key: record.public_key,
      checkpoints: [record],
    };
    expect(isTransparencyBundle(bundle)).toBe(true);
    expect(isTransparencyBundle({ ...bundle, format: "OTHER" })).toBe(false);
    expect(
      isTransparencyBundle({ ...bundle, checkpoints: [{ bogus: true }] })
    ).toBe(false);
  });

  it("checkpointPayloadOf strips exactly the signature envelope", () => {
    const record = signRecord(samplePayload(), randomBytes(32));
    const payload = checkpointPayloadOf(record);
    expect(payload).toEqual(samplePayload());
    expect("signature" in payload).toBe(false);
    expect("public_key" in payload).toBe(false);
  });
});
