/**
 * Pure contract tests for the inert Q5 catalog, index, and overlay wire formats.
 */

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ED25519_TORSION_SUBGROUP, ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import { fromBase64urlStrict, toBase64url } from "../../src/core/encoding.js";
import {
  SPDX_GENERATED_EXCEPTION_ROWS,
  SPDX_GENERATED_LICENSE_ROWS,
} from "../../src/intelligence/catalog-v3/spdx/spdx-tables.generated.js";
import golden from "../fixtures/catalog-v3/catalog-body-golden.json";
import wireGolden from "../fixtures/catalog-v3/wire-boundaries-golden.json";
import {
  ASSURANCES,
  CATALOG_V3_DOMAIN,
  CATALOG_INDEX_V1_DOMAIN,
  CATALOG_INDEX_SIGNING_BODY_MAX_BYTES,
  CATALOG_SIGNING_BODY_MAX_BYTES,
  CATALOG_SURFACE_ORDER,
  COMPILED_CATALOG_KEY_POLICY_DIGEST,
  COMPILED_CATALOG_KEYRING,
  COMPILED_INDEX_CHECKPOINT,
  HARDWARE_TIERS,
  MAX_OVERLAY_ENTRIES,
  OVERLAY_SIGNING_BODY_MAX_BYTES,
  OVERLAY_V1_DOMAIN,
  buildDomainSignaturePreimage,
  canonicalizeJson,
  computeCanonicalSha256,
  deriveCatalogKeyringSha256,
  deriveOverlaySignerKeyId,
  effectiveSurfaceFloor,
  isDomainSignaturePreimageWithinLimit,
  parseCatalogBodyV3,
  parseCatalogIndexBodyV1,
  parseCatalogJson,
  parseOverlayBodyV1,
  parseUntrustedCatalogContinuityObservationV3,
  parseUntrustedCatalogIndexContinuityObservationV1,
  parseSpdxExpression,
  validateCatalogOverlayCombination,
  validateCatalogKeyring,
  verifyAndParseSignedCatalogIndexSegmentV1,
  verifyAndParseSignedCatalogIndexJsonV1,
  verifyAndParseSignedCatalogJsonV3,
  verifyAndParseSignedCatalogV3,
  verifyAndParseSignedOverlayJsonV1,
  verifyAndParseSignedOverlayV1,
  type CatalogBodyV3,
  type CatalogKeyEpoch,
  type CatalogModelEntryV3,
  type OverlayBodyV1,
} from "../../src/intelligence/model-catalog-v3.js";

type CorpusBoundary = {
  name: string;
  external_fixture?: string;
  domain: string;
  body?: unknown;
  canonical_body?: string;
  body_sha256?: string;
  signature?: string;
  key_field: "signing_key_id" | "signer_key_id";
  key_id: string;
  verdict: "accept";
};

type CorpusCase = {
  name: string;
  boundary: string;
  operation: "parse_body" | "parse_envelope" | "verify_signature";
  path?: Array<string | number>;
  value?: unknown;
  delete_path?: Array<string | number>;
  envelope_path?: Array<string | number>;
  envelope_value?: unknown;
  delete_envelope_path?: Array<string | number>;
  mutation?: "append_index_gap" | "append_index_duplicate_release" | "append_index_duplicate_asset" | "append_index_duplicate_envelope" | "append_index_duplicate_body" | "append_index_cross_digest" | "append_duplicate_identity" | "overflow_collection" | "pad_signature" | "noncanonical_signature" | "short_signature" | "zero_signature";
  domain?: string;
  verdict: string;
};

type MutableDeep<T> = T extends readonly (infer Item)[]
  ? MutableDeep<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: MutableDeep<T[Key]> }
    : T;

const corpus = wireGolden as unknown as {
  schema: string;
  test_public_key: string;
  derived_test_signer_key_id: string;
  test_catalog_keyring: CatalogKeyEpoch[];
  boundaries: CorpusBoundary[];
  contract_cases: CorpusCase[];
  generated_size_cases: Array<{ name: string; measurement: "catalog_domain_preimage_bytes"; preimage_bytes: number; verdict: string }>;
  spdx: Array<{ source: string; canonical?: string; verdict: string }>;
  raw_adversarial: Array<{ name: string; operation: "parse_catalog_json" | "parse_spdx"; text: string; max_bytes?: number; verdict: string }>;
};
const consumedCorpusRows = {
  boundaries: new Set<string>(),
  spdx: new Set<string>(),
  contract_cases: new Set<string>(),
  generated_size_cases: new Set<string>(),
  raw_adversarial: new Set<string>(),
};
const EXPECTED_CORPUS_ROW_DIGESTS = Object.freeze({
  boundaries: "f7cc089d23cbadd6b781a0210f04aac5112c74d18773647614854b31f7df8978",
  spdx: "0b3aa9fe04852ae6a03a8ab0b90bada24db6f14a7f984a4c03840984f5b931b4",
  contract_cases: "953f924e3346ad1dff3eddce1d715f2763acb670a7a0875c261a8019c16113ab",
  generated_size_cases: "301b9509c8fa922f68e359b7e5c8a5425bf0ff2b9bb19fb2e9bbb235882ed4ec",
  raw_adversarial: "17c77d34a7bb2e27375d8ee69ca6acc2031aed8d9b3464dff6f6042291392072",
});

const TEST_CATALOG_KEYRING: readonly CatalogKeyEpoch[] = Object.freeze(
  corpus.test_catalog_keyring.map((entry) => Object.freeze(entry)),
);
const TEST_CATALOG_KEYRING_SHA256 = computeCanonicalSha256(TEST_CATALOG_KEYRING);
const TEST_OVERLAY_SIGNER_KEY_ID = corpus.derived_test_signer_key_id;

function validateTestCombination(
  catalog: unknown,
  overlay: unknown,
  bindingId: unknown,
  versionFloor: unknown,
  catalogKeyringSha256: unknown = TEST_CATALOG_KEYRING_SHA256,
  overlaySignerKeyId: unknown = TEST_OVERLAY_SIGNER_KEY_ID,
) {
  return validateCatalogOverlayCombination(
    catalog,
    overlay,
    bindingId,
    versionFloor,
    catalogKeyringSha256,
    overlaySignerKeyId,
  );
}

function corpusBoundary(name: string): CorpusBoundary {
  const boundary = corpus.boundaries.find((candidate) => candidate.name === name);
  if (!boundary) throw new Error(`missing corpus boundary: ${name}`);
  return boundary;
}

function corpusBody(boundary: CorpusBoundary): unknown {
  if (boundary.external_fixture === "catalog-body-golden.json") return structuredClone(golden.body);
  if (boundary.external_fixture !== undefined || boundary.body === undefined) throw new Error(`invalid external fixture: ${boundary.name}`);
  return structuredClone(boundary.body);
}

function setFixturePath(root: unknown, path: readonly (string | number)[], value: unknown): void {
  let cursor = root;
  for (let index = 0; index < path.length - 1; index++) {
    const key = path[index]!;
    if (typeof key === "number") {
      if (!Array.isArray(cursor)) throw new Error("fixture path is not an array");
      cursor = cursor[key];
    } else {
      if (typeof cursor !== "object" || cursor === null || Array.isArray(cursor)) throw new Error("fixture path is not an object");
      cursor = (cursor as Record<string, unknown>)[key];
    }
  }
  const leaf = path.at(-1)!;
  if (typeof leaf === "number") {
    if (!Array.isArray(cursor)) throw new Error("fixture leaf is not an array");
    cursor[leaf] = structuredClone(value);
  } else {
    if (typeof cursor !== "object" || cursor === null || Array.isArray(cursor)) throw new Error("fixture leaf is not an object");
    (cursor as Record<string, unknown>)[leaf] = structuredClone(value);
  }
}

function deleteFixturePath(root: unknown, path: readonly (string | number)[]): void {
  let cursor = root;
  for (let index = 0; index < path.length - 1; index++) {
    const key = path[index]!;
    if (typeof key === "number") {
      if (!Array.isArray(cursor)) throw new Error("fixture path is not an array");
      cursor = cursor[key];
    } else {
      if (typeof cursor !== "object" || cursor === null || Array.isArray(cursor)) throw new Error("fixture path is not an object");
      cursor = (cursor as Record<string, unknown>)[key];
    }
  }
  const leaf = path.at(-1)!;
  if (typeof cursor !== "object" || cursor === null) throw new Error("fixture leaf parent is not an object");
  if (typeof leaf === "number") {
    if (!Array.isArray(cursor)) throw new Error("fixture leaf is not an array");
    cursor.splice(leaf, 1);
  } else {
    delete (cursor as Record<string, unknown>)[leaf];
  }
}

function applyStructuralMutation(body: unknown, boundary: CorpusBoundary, mutation: CorpusCase["mutation"]): void {
  if (mutation === "append_index_gap") {
    const indexBody = body as { entries: Array<Record<string, unknown>>; highest_catalog_version: number };
    const gap = structuredClone(indexBody.entries[0]!);
    gap.catalog_version = 3;
    gap.catalog_release_id = 1003;
    gap.catalog_asset_id = 2003;
    indexBody.entries.push(gap);
    indexBody.highest_catalog_version = 3;
  } else if (mutation?.startsWith("append_index_duplicate_") || mutation === "append_index_cross_digest") {
    const indexBody = body as { entries: Array<Record<string, unknown>>; index_version: number; previous_index_body_sha256: string | null; highest_catalog_version: number };
    const first = indexBody.entries[0]!;
    const second: Record<string, unknown> = {
      ...structuredClone(first), catalog_version: 2, catalog_release_id: 1002,
      catalog_asset_id: 2002, envelope_sha256: "5".repeat(64), body_sha256: "6".repeat(64),
    };
    const duplicateFields: Readonly<Record<string, string>> = {
      append_index_duplicate_release: "catalog_release_id",
      append_index_duplicate_asset: "catalog_asset_id",
      append_index_duplicate_envelope: "envelope_sha256",
      append_index_duplicate_body: "body_sha256",
      append_index_cross_digest: "body_sha256",
    };
    const field = duplicateFields[mutation];
    if (!field) throw new Error(`unknown index duplicate mutation: ${mutation}`);
    second[field] = mutation === "append_index_cross_digest" ? first.envelope_sha256 : first[field];
    indexBody.entries.push(second);
    indexBody.index_version = 2;
    indexBody.highest_catalog_version = 2;
    indexBody.previous_index_body_sha256 = "a".repeat(64);
  } else if (mutation === "append_duplicate_identity") {
    const field = boundary.domain === CATALOG_V3_DOMAIN ? "models" : "entries";
    const collection = (body as Record<string, Array<Record<string, unknown>>>)[field];
    const duplicate = structuredClone(collection[0]!);
    duplicate.model_id = `${String(collection.at(-1)!.model_id)}z`;
    collection.push(duplicate);
  } else if (mutation === "overflow_collection") {
    if (boundary.domain === CATALOG_INDEX_V1_DOMAIN) {
      const indexBody = body as { entries: Array<Record<string, unknown>>; highest_catalog_version: number };
      const template = indexBody.entries[0]!;
      indexBody.entries = Array.from({ length: 65 }, (_, index) => ({
        ...structuredClone(template),
        catalog_version: index + 1,
        catalog_release_id: 1001 + index,
        catalog_asset_id: 2001 + index,
      }));
      indexBody.highest_catalog_version = 65;
    } else {
      const field = boundary.domain === CATALOG_V3_DOMAIN ? "models" : "entries";
      const limit = boundary.domain === CATALOG_V3_DOMAIN ? 33 : 65;
      const collection = (body as Record<string, Array<Record<string, unknown>>>)[field];
      const template = collection[0]!;
      (body as Record<string, unknown>)[field] = Array.from({ length: limit }, (_, index) => {
        const item = structuredClone(template);
        item.model_id = `m${index.toString().padStart(2, "0")}`;
        const identity = item.identity as Record<string, unknown>;
        identity.tag = `t${index.toString().padStart(2, "0")}`;
        return item;
      });
    }
  }
}

function corpusEnvelope(boundary: CorpusBoundary, body: unknown): Record<string, unknown> {
  const signature = boundary.signature ?? golden.signature;
  return boundary.key_field === "signer_key_id"
    ? { body, signature, signer_key_id: boundary.key_id }
    : { body, signature, signing_key_id: boundary.key_id };
}

function verifyCorpusEnvelope(boundary: CorpusBoundary, envelope: unknown) {
  if (boundary.domain === CATALOG_V3_DOMAIN) return verifyAndParseSignedCatalogV3(envelope, TEST_CATALOG_KEYRING);
  if (boundary.domain === CATALOG_INDEX_V1_DOMAIN) return verifyAndParseSignedCatalogIndexSegmentV1(envelope, TEST_CATALOG_KEYRING);
  return verifyAndParseSignedOverlayV1(envelope, fromBase64urlStrict(corpus.test_public_key));
}

function expectDeeplyFrozen(value: unknown, seen = new WeakSet<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const nested of Object.values(value as Record<string, unknown>)) {
    expectDeeplyFrozen(nested, seen);
  }
}

function executeCorpusOperation(
  fixture: CorpusCase,
  boundary: CorpusBoundary,
  body: unknown,
  envelope: unknown,
) {
  switch (fixture.operation) {
    case "parse_body":
      if (boundary.domain === CATALOG_V3_DOMAIN) return parseCatalogBodyV3(body);
      if (boundary.domain === CATALOG_INDEX_V1_DOMAIN) return parseCatalogIndexBodyV1(body);
      return parseOverlayBodyV1(body);
    case "parse_envelope":
    case "verify_signature":
      return verifyCorpusEnvelope(boundary, envelope);
    default: {
      const exhaustive: never = fixture.operation;
      throw new Error(`unknown corpus operation: ${String(exhaustive)}`);
    }
  }
}

function runIndependentPythonVerifier(verifier: string) {
  const probe = spawnSync("python3", ["--version"], {
    encoding: "utf8",
    timeout: 5_000,
  });
  if (probe.error) {
    throw new Error(`catalog parity requires Python 3.10+: ${probe.error.message}`);
  }
  const versionText = `${probe.stdout}${probe.stderr}`.trim();
  const version = /^Python (\d+)\.(\d+)\./.exec(versionText);
  if (probe.status !== 0 || !version || Number(version[1]) < 3 || (Number(version[1]) === 3 && Number(version[2]) < 10)) {
    throw new Error(`catalog parity requires Python 3.10+, found: ${versionText || `exit ${probe.status}`}`);
  }
  // 60_000 = generous ceiling for the pure-Python Ed25519 verifier (~90 scalar
  // multiplications with no native acceleration) on a loaded or slower-single-thread CI
  // runner; paired with the it()'s own 90_000 ms vitest timeout below so the process
  // timeout always fires first and produces a diagnosable spawnSync result.
  const result = spawnSync("python3", ["-O", verifier], {
    encoding: "utf8",
    env: { ...process.env, PYTHONHASHSEED: "0" },
    timeout: 60_000,
    maxBuffer: 1_048_576,
  });
  if (result.error) throw new Error(`catalog parity verifier failed to start: ${result.error.message}`);
  return result;
}

function buildCatalogCapBody(targetBytes: number): CatalogBodyV3 {
  const component = (prefix: string, index: number): string =>
    `${prefix}${index.toString().padStart(2, "0")}`.padEnd(64, "x");
  const models: MutableDeep<CatalogModelEntryV3>[] = Array.from({ length: 32 }, (_, index) => ({
    model_id: component("m", index),
    identity: {
      registry: "registry.ollama.ai",
      namespace: component("n", index),
      model: component("o", index),
      tag: component("t", index),
      ollama_manifest_sha256: ((index % 9) + 1).toString().repeat(64),
    },
    assurance: "immune",
    license: {
      spdx: "custom",
      custom_name: "c".repeat(120),
      source_url: `https://example.com/${"a".repeat(236)}`,
      evidence_sha256: "a".repeat(64),
    },
    hardware_tier: "baseline",
  }));
  const body = structuredClone(golden.body) as unknown as MutableDeep<CatalogBodyV3>;
  body.catalog_version = 2_147_483_647;
  body.previous_catalog_body_sha256 = "b".repeat(64);
  body.models = models;
  let size = buildDomainSignaturePreimage(CATALOG_V3_DOMAIN, body).length;
  for (const model of body.models) {
    while (size > targetBytes && model.license.custom_name!.length > 1) {
      model.license.custom_name = model.license.custom_name!.slice(0, -1);
      size--;
    }
  }
  expect(size).toBe(targetBytes);
  return body;
}

function makeNonCanonicalEd25519Signature(signature: string): string {
  const bytes = fromBase64urlStrict(signature).slice();
  let scalar = 0n;
  for (let index = 63; index >= 32; index--) scalar = (scalar << 8n) | BigInt(bytes[index]!);
  scalar += (2n ** 252n) + 27742317777372353535851937790883648493n;
  for (let index = 32; index < 64; index++) {
    bytes[index] = Number(scalar & 0xffn);
    scalar >>= 8n;
  }
  return toBase64url(bytes);
}

function littleEndian32(value: bigint): Uint8Array {
  const result = new Uint8Array(32);
  for (let index = 0; index < result.length; index++) {
    result[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return result;
}

function makeIdentityREd25519Signature(message: Uint8Array): { publicKey: Uint8Array; signature: string } {
  const publicKey = ed25519.Point.BASE.toBytes();
  const identityR = new Uint8Array(32);
  identityR[0] = 1;
  const digest = createHash("sha512").update(identityR).update(publicKey).update(message).digest();
  let challenge = 0n;
  for (let index = digest.length - 1; index >= 0; index--) challenge = (challenge << 8n) | BigInt(digest[index]!);
  challenge %= (2n ** 252n) + 27742317777372353535851937790883648493n;
  const signature = new Uint8Array(64);
  signature.set(identityR);
  signature.set(littleEndian32(challenge), 32);
  // For A=B and secret scalar one: [S]B = identity + H(R,A,m)A.
  expect(ed25519.verify(signature, message, publicKey, { zip215: false })).toBe(true);
  return { publicKey, signature: toBase64url(signature) };
}

function keyringWithPublicKey(publicKey: Uint8Array): readonly CatalogKeyEpoch[] {
  return [{ ...TEST_CATALOG_KEYRING[0]!, pubkey: toBase64url(publicKey) }];
}

const LOCAL_TEST_PRIVATE_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const LOCAL_TEST_PUBLIC_KEY = ed25519.getPublicKey(LOCAL_TEST_PRIVATE_KEY);
const ROTATED_TEST_PRIVATE_KEY = Uint8Array.from({ length: 32 }, (_, index) => 32 - index);
const ROTATED_TEST_PUBLIC_KEY = ed25519.getPublicKey(ROTATED_TEST_PRIVATE_KEY);

function signLocal(domain: string, body: unknown): string {
  return toBase64url(ed25519.sign(buildDomainSignaturePreimage(domain, body), LOCAL_TEST_PRIVATE_KEY));
}

function verifyLocalCatalog(body: unknown) {
  const keyring = keyringWithPublicKey(LOCAL_TEST_PUBLIC_KEY);
  return verifyAndParseSignedCatalogV3({
    body,
    signature: signLocal(CATALOG_V3_DOMAIN, body),
    signing_key_id: "cat-epoch-1",
  }, keyring);
}

function verifyLocalOverlay(body: unknown) {
  const keyId = deriveOverlaySignerKeyId(LOCAL_TEST_PUBLIC_KEY);
  if (!keyId.ok) throw new Error("test operator key unexpectedly invalid");
  return verifyAndParseSignedOverlayV1({
    body,
    signature: signLocal(OVERLAY_V1_DOMAIN, body),
    signer_key_id: keyId.value,
  }, LOCAL_TEST_PUBLIC_KEY);
}

function localCatalogKeyringSha256(): string {
  const digest = deriveCatalogKeyringSha256(keyringWithPublicKey(LOCAL_TEST_PUBLIC_KEY));
  if (!digest.ok) throw new Error("test catalog keyring unexpectedly invalid");
  return digest.value;
}

function localOverlaySignerKeyId(): string {
  const keyId = deriveOverlaySignerKeyId(LOCAL_TEST_PUBLIC_KEY);
  if (!keyId.ok) throw new Error("test operator key unexpectedly invalid");
  return keyId.value;
}

function verifyLocalIndex(body: unknown, keyring = keyringWithPublicKey(LOCAL_TEST_PUBLIC_KEY)) {
  return verifyAndParseSignedCatalogIndexSegmentV1({
    body,
    signature: signLocal(CATALOG_INDEX_V1_DOMAIN, body),
    signing_key_id: "cat-epoch-1",
  }, keyring);
}

function twoEpochKeyring(firstStatus: "retired" | "revoked"): readonly CatalogKeyEpoch[] {
  return [
    {
      ...TEST_CATALOG_KEYRING[0]!,
      pubkey: toBase64url(LOCAL_TEST_PUBLIC_KEY),
      status: firstStatus,
      max_catalog_version: 1,
      max_index_version: 1,
    },
    {
      ...TEST_CATALOG_KEYRING[0]!,
      epoch: 2,
      signing_key_id: "cat-epoch-2",
      pubkey: toBase64url(ROTATED_TEST_PUBLIC_KEY),
      min_catalog_version: 2,
      min_index_version: 2,
    },
  ];
}

function verifyRotatedIndex(body: unknown, keyring: readonly CatalogKeyEpoch[]) {
  const signature = toBase64url(ed25519.sign(
    buildDomainSignaturePreimage(CATALOG_INDEX_V1_DOMAIN, body),
    ROTATED_TEST_PRIVATE_KEY,
  ));
  return verifyAndParseSignedCatalogIndexSegmentV1({
    body,
    signature,
    signing_key_id: "cat-epoch-2",
  }, keyring);
}

describe("model catalog v3 closed contracts", () => {
  it("pins the three signing domains and explicit genesis sentinel", () => {
    expect(CATALOG_V3_DOMAIN).toBe("sanctuary.model-catalog.v3");
    expect(OVERLAY_V1_DOMAIN).toBe("sanctuary.model-overlay.v1");
    expect(COMPILED_INDEX_CHECKPOINT).toEqual({
      index_version: 0,
      index_body_sha256: null,
      highest_catalog_version: 0,
      highest_catalog_body_sha256: null,
      signing_key_id: "cat-epoch-1",
    });
    expect(MAX_OVERLAY_ENTRIES).toBe(64);
    expect(COMPILED_CATALOG_KEY_POLICY_DIGEST).toBe("cdc2dce6bbec11b5c931ce8a4953c66266d10d597117843aa64fa99c9384e4c8");
    expect(CATALOG_SURFACE_ORDER).toEqual([
      "concierge", "direct-agent-gate-advisor", "sentinel-scoring",
      "gate-explanation", "privacy-filter-tier-2", "template-suggestion",
    ]);
    expect(Object.isFrozen(ASSURANCES)).toBe(true);
    expect(Object.isFrozen(HARDWARE_TIERS)).toBe(true);
    expect(Object.isFrozen(SPDX_GENERATED_LICENSE_ROWS)).toBe(true);
    expect(Object.isFrozen(SPDX_GENERATED_EXCEPTION_ROWS)).toBe(true);
    expect(SPDX_GENERATED_LICENSE_ROWS.every((row) => Object.isFrozen(row))).toBe(true);
    expect(SPDX_GENERATED_EXCEPTION_ROWS.every((row) => Object.isFrozen(row))).toBe(true);
    expect(validateCatalogKeyring(COMPILED_CATALOG_KEYRING).ok).toBe(true);
    expect(effectiveSurfaceFloor("sentinel-scoring", "light")).toBe("immune");
    expect(effectiveSurfaceFloor("concierge", "immune")).toBe("immune");

    const reusedDecodedKey = [
      {
        ...COMPILED_CATALOG_KEYRING[0]!,
        status: "revoked",
        max_catalog_version: 1,
        max_index_version: 1,
      },
      {
        ...COMPILED_CATALOG_KEYRING[0]!,
        epoch: 2,
        signing_key_id: "cat-epoch-2",
        min_catalog_version: 2,
        min_index_version: 2,
      },
    ] as const;
    expect(validateCatalogKeyring(reusedDecodedKey)).toEqual({
      ok: false,
      reason: "invalid_value",
    });
    const revokedWithoutSuccessor = [{
      ...COMPILED_CATALOG_KEYRING[0]!,
      status: "revoked" as const,
      max_catalog_version: 1,
      max_index_version: 1,
    }];
    expect(validateCatalogKeyring(revokedWithoutSuccessor)).toEqual({
      ok: false,
      reason: "invalid_value",
    });
  });

  it("rejects noncanonical, torsion-bearing, and identity Ed25519 principals", () => {
    const noncanonicalY = littleEndian32((2n ** 255n) - 19n);
    expect(validateCatalogKeyring(keyringWithPublicKey(noncanonicalY))).toEqual({
      ok: false,
      reason: "invalid_value",
    });

    const torsionPoint = ed25519.Point.fromBytes(
      Buffer.from(ED25519_TORSION_SUBGROUP[1]!, "hex"),
      true,
    );
    const torsionBearingKey = ed25519.Point.BASE.add(torsionPoint).toBytes();
    const decodedTorsionBearing = ed25519.Point.fromBytes(torsionBearingKey, false);
    expect(decodedTorsionBearing.isSmallOrder()).toBe(false);
    expect(decodedTorsionBearing.isTorsionFree()).toBe(false);
    expect(validateCatalogKeyring(keyringWithPublicKey(torsionBearingKey))).toEqual({
      ok: false,
      reason: "invalid_value",
    });

    // For A=identity, choosing R=[S]B satisfies the naive verification
    // equation [S]B=R+[k]A for every message. Principal validation must reject
    // this constructive existential forgery before signature verification.
    const identityKey = new Uint8Array(32); identityKey[0] = 1;
    const scalar = littleEndian32(1n);
    const rPoint = ed25519.Point.BASE.toBytes();
    const identityPoint = ed25519.Point.fromBytes(identityKey, false);
    const decodedR = ed25519.Point.fromBytes(rPoint, false);
    expect(ed25519.Point.BASE.multiply(1n).equals(
      decodedR.add(identityPoint.multiply(42n)),
    )).toBe(true);
    const forgedSignature = toBase64url(Uint8Array.from([...rPoint, ...scalar]));
    const envelope = {
      body: golden.body,
      signature: forgedSignature,
      signing_key_id: "cat-epoch-1",
    };
    expect(validateCatalogKeyring(keyringWithPublicKey(identityKey))).toEqual({
      ok: false,
      reason: "invalid_value",
    });
    expect(verifyAndParseSignedCatalogV3(envelope, keyringWithPublicKey(identityKey))).toEqual({
      ok: false,
      reason: "invalid_value",
    });
    expect(deriveOverlaySignerKeyId(identityKey)).toEqual({ ok: false, reason: "bad_signature" });
    for (const notBytes of [null, undefined, [], {}, "bytes", new DataView(new ArrayBuffer(32))]) {
      expect(deriveOverlaySignerKeyId(notBytes as unknown as Uint8Array)).toEqual({
        ok: false,
        reason: "bad_pinned_key_length",
      });
    }
    const hostileBytes = new Proxy(new Uint8Array(32), {
      getPrototypeOf() { throw new Error("hostile typed-array proxy"); },
    });
    expect(deriveOverlaySignerKeyId(hostileBytes)).toEqual({
      ok: false,
      reason: "bad_pinned_key_length",
    });
    const validBytes = fromBase64urlStrict(corpus.test_public_key);
    expect(deriveOverlaySignerKeyId(Buffer.from(validBytes)))
      .toEqual(deriveOverlaySignerKeyId(validBytes));
  });

  it("snapshots hostile public inputs once and refuses malformed keyrings", () => {
    for (const malformed of [null, {}, "keyring", [null], ["epoch"], [{ epoch: 1 }]]) {
      expect(validateCatalogKeyring(malformed)).toEqual({ ok: false, reason: "invalid_value" });
    }
    const throwingKeyring = new Proxy([], {
      ownKeys() { throw new Error("hostile ownKeys trap"); },
    });
    expect(validateCatalogKeyring(throwingKeyring)).toEqual({ ok: false, reason: "invalid_value" });
    let keyringGetterCalls = 0;
    const accessorEpoch = { ...COMPILED_CATALOG_KEYRING[0]! } as Record<string, unknown>;
    Object.defineProperty(accessorEpoch, "pubkey", {
      enumerable: true,
      get() { keyringGetterCalls++; return COMPILED_CATALOG_KEYRING[0]!.pubkey; },
    });
    expect(validateCatalogKeyring([accessorEpoch])).toEqual({ ok: false, reason: "invalid_value" });
    expect(verifyAndParseSignedCatalogV3(
      { body: golden.body, signature: golden.signature, signing_key_id: "cat-epoch-1" },
      [accessorEpoch as unknown as CatalogKeyEpoch],
    )).toEqual({ ok: false, reason: "invalid_value" });
    expect(keyringGetterCalls).toBe(0);

    let getterCalls = 0;
    const accessorBody = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(accessorBody, "schema", {
      enumerable: true,
      get() { getterCalls++; return CATALOG_V3_DOMAIN; },
    });
    expect(parseCatalogBodyV3(accessorBody)).toEqual({ ok: false, reason: "invalid_value" });
    expect(getterCalls).toBe(0);

    const throwingBody = new Proxy({}, {
      getOwnPropertyDescriptor() { throw new Error("hostile descriptor trap"); },
      ownKeys() { return ["schema"]; },
    });
    expect(parseCatalogBodyV3(throwingBody)).toEqual({ ok: false, reason: "invalid_value" });
    expect(parseOverlayBodyV1(throwingBody)).toEqual({ ok: false, reason: "invalid_value" });
    expect(parseCatalogIndexBodyV1(throwingBody)).toEqual({ ok: false, reason: "invalid_value" });
    expect(parseUntrustedCatalogContinuityObservationV3(throwingBody)).toEqual({ ok: false, reason: "invalid_value" });
    expect(parseUntrustedCatalogIndexContinuityObservationV1(throwingBody)).toEqual({ ok: false, reason: "invalid_value" });
    expect(validateTestCombination(throwingBody, {}, "a".repeat(32), 0)).toEqual({
      ok: false,
      reason: "unauthenticated_input",
    });
    expect(verifyAndParseSignedCatalogV3(throwingBody, TEST_CATALOG_KEYRING)).toEqual({
      ok: false,
      reason: "invalid_value",
    });
    expect(() => canonicalizeJson(accessorBody)).toThrow("non-JSON input");
    expect(getterCalls).toBe(0);

    let proxyGetCalls = 0;
    const descriptorOnlyBody = new Proxy(structuredClone(golden.body), {
      get() { proxyGetCalls++; throw new Error("ordinary property access is forbidden"); },
    });
    expect(parseCatalogBodyV3(descriptorOnlyBody).ok).toBe(true);
    expect(proxyGetCalls).toBe(0);

    let textProxyCalls = 0;
    const hostileText = new Proxy(new String("{}"), {
      get() { textProxyCalls++; throw new Error("must not coerce hostile text"); },
      getOwnPropertyDescriptor() { textProxyCalls++; throw new Error("must not inspect hostile text"); },
    });
    let parserCalls = 0;
    expect(parseCatalogJson(hostileText, 1024, (value) => {
      parserCalls++;
      return parseCatalogBodyV3(value);
    })).toEqual({
      ok: false,
      reason: "invalid_type",
    });
    expect(textProxyCalls).toBe(0);
    expect(parserCalls).toBe(0);
    expect(parseSpdxExpression(hostileText)).toEqual({ ok: false, reason: "invalid_spdx" });
    expect(textProxyCalls).toBe(0);
  });

  it("accepts the closed Sanctuary SPDX profile and exact case rules", () => {
    expect(parseSpdxExpression("MIT AND Apache-2.0").ok).toBe(true);
    expect(parseSpdxExpression("DocumentRef-Doc:LicenseRef-Local WITH DocumentRef-Doc:AdditionRef-Note")).toEqual({
      ok: true,
      value: "DocumentRef-doc:LicenseRef-local WITH DocumentRef-doc:AdditionRef-note",
    });
    expect(parseSpdxExpression("MIT And Apache-2.0")).toEqual({ ok: false, reason: "invalid_spdx" });
    expect(parseSpdxExpression("documentRef-doc:LicenseRef-local")).toEqual({ ok: false, reason: "invalid_spdx" });
    const lowercaseBody = structuredClone(golden.body);
    lowercaseBody.models[0]!.license.spdx = "apache-2.0";
    const parsed = parseCatalogJson(JSON.stringify(lowercaseBody), CATALOG_SIGNING_BODY_MAX_BYTES, parseCatalogBodyV3);
    expect(parsed).toEqual({ ok: false, reason: "invalid_spdx" });
  });

  it("keeps body parsers distinct and closed", () => {
    expect(parseCatalogJson(JSON.stringify({ schema: OVERLAY_V1_DOMAIN }), CATALOG_SIGNING_BODY_MAX_BYTES, parseCatalogBodyV3)).toEqual({ ok: false, reason: "missing_key" });
    expect(parseCatalogJson(JSON.stringify({ schema: CATALOG_V3_DOMAIN }), CATALOG_SIGNING_BODY_MAX_BYTES, parseOverlayBodyV1)).toEqual({ ok: false, reason: "missing_key" });
    expect(parseCatalogJson("{}", CATALOG_SIGNING_BODY_MAX_BYTES, parseCatalogIndexBodyV1)).toEqual({ ok: false, reason: "missing_key" });
  });

  // 90_000 ms vitest timeout (file default is 30_000 ms): this test shells out to the
  // pure-Python Ed25519 verifier via runIndependentPythonVerifier, whose own spawnSync
  // timeout is 60_000 ms; the vitest timeout must exceed that so a slow-but-legitimate
  // run reports as a spawnSync timeout, not a vitest-level test-timeout with less detail.
  it("pins cross-language JCS bytes, digest, and Ed25519 signature", () => {
    expect(canonicalizeJson(golden.body)).toBe(golden.canonical_body);
    expect(computeCanonicalSha256(golden.body)).toBe(golden.canonical_body_sha256);
    expect(buildDomainSignaturePreimage(golden.domain, golden.body).length).toBeLessThanOrEqual(CATALOG_SIGNING_BODY_MAX_BYTES);
    expect(verifyAndParseSignedCatalogV3({ body: golden.body, signature: golden.signature, signing_key_id: "cat-epoch-1" }, TEST_CATALOG_KEYRING).ok).toBe(true);
    const parsed = parseCatalogJson(JSON.stringify(golden.body), CATALOG_SIGNING_BODY_MAX_BYTES, parseCatalogBodyV3);
    expect(parsed.ok).toBe(true);

    const verifier = fileURLToPath(new URL("../fixtures/catalog-v3/verify-golden.py", import.meta.url));
    const python = runIndependentPythonVerifier(verifier);
    expect(python).toMatchObject({ status: 0, stderr: "" });
    expect(python.stdout).toMatch(/^S1_PARITY_OK boundaries=3 contract_cases=100 generated_size_cases=2 raw_adversarial=5 spdx=5\n$/);
  }, 90_000);

  it("deep-freezes every successful verified envelope and preserves its content digest", () => {
    for (const name of [
      "catalog-body-and-envelope",
      "catalog-index-body-and-envelope",
      "overlay-body-and-envelope",
    ]) {
      const boundary = corpusBoundary(name);
      const result = verifyCorpusEnvelope(boundary, corpusEnvelope(boundary, corpusBody(boundary)));
      expect(result.ok, name).toBe(true);
      if (!result.ok) throw new Error(`${name}: verification unexpectedly failed`);

      expect(Object.isFrozen(result), `${name}: success result`).toBe(true);
      expectDeeplyFrozen(result.value);
      const beforeContent = canonicalizeJson(result.value);
      const beforeBodyDigest = computeCanonicalSha256(result.value.body);
      const envelope = result.value as unknown as Record<string, unknown>;
      const body = envelope.body as Record<string, unknown>;
      const collectionName = boundary.domain === CATALOG_V3_DOMAIN ? "models" : "entries";
      const collection = body[collectionName] as unknown[];
      const firstEntry = collection[0] as Record<string, unknown>;
      const entryProperty = boundary.domain === CATALOG_INDEX_V1_DOMAIN ? "catalog_version" : "model_id";
      const entryReplacement: unknown = boundary.domain === CATALOG_INDEX_V1_DOMAIN ? 2 : "mutated";

      expect(Reflect.set(result, "value", {}), `${name}: result mutation`).toBe(false);
      expect(Reflect.set(envelope, "signature", "A".repeat(86)), `${name}: envelope mutation`).toBe(false);
      expect(Reflect.set(body, "issued_at", "2099-01-01T00:00:00Z"), `${name}: body mutation`).toBe(false);
      expect(Reflect.set(collection, 0, {}), `${name}: array mutation`).toBe(false);
      expect(Reflect.set(firstEntry, entryProperty, entryReplacement), `${name}: entry mutation`).toBe(false);
      if ("identity" in firstEntry) {
        expect(
          Reflect.set(firstEntry.identity as Record<string, unknown>, "tag", "mutated"),
          `${name}: nested identity mutation`,
        ).toBe(false);
      }
      expect(canonicalizeJson(result.value), `${name}: content`).toBe(beforeContent);
      expect(computeCanonicalSha256(result.value.body), `${name}: body digest`).toBe(beforeBodyDigest);
    }
  });

  it("executes every body and envelope boundary in the portable parity corpus", () => {
    const publicKey = fromBase64urlStrict(corpus.test_public_key);
    expect(corpus.schema).toBe("sanctuary.catalog-v3-parity-corpus.v1");
    expect(toBase64url(createHash("sha256").update(publicKey).digest())).toBe(corpus.derived_test_signer_key_id);
    for (const boundary of corpus.boundaries) {
      consumedCorpusRows.boundaries.add(boundary.name);
      const body = corpusBody(boundary);
      const canonicalBody = boundary.canonical_body ?? golden.canonical_body;
      const bodySha256 = boundary.body_sha256 ?? golden.canonical_body_sha256;
      expect(canonicalizeJson(body), boundary.name).toBe(canonicalBody);
      expect(computeCanonicalSha256(body), boundary.name).toBe(bodySha256);
      if (boundary.key_field === "signer_key_id") expect(boundary.key_id).toBe(corpus.derived_test_signer_key_id);
      const envelope = corpusEnvelope(boundary, body);
      const parsed = verifyCorpusEnvelope(boundary, envelope);
      expect(parsed.ok ? "accept" : parsed.reason, boundary.name).toBe(boundary.verdict);
    }
    for (const fixture of corpus.spdx) {
      consumedCorpusRows.spdx.add(fixture.source);
      const parsed = parseSpdxExpression(fixture.source);
      if (fixture.verdict === "accept") expect(parsed).toEqual({ ok: true, value: fixture.canonical });
      else expect(parsed).toEqual({ ok: false, reason: fixture.verdict });
    }
  });

  it("executes every accepted and adversarial corpus verdict through the TypeScript implementation", () => {
    for (const fixture of corpus.contract_cases) {
      consumedCorpusRows.contract_cases.add(fixture.name);
      const boundary = corpusBoundary(fixture.boundary);
      const body = corpusBody(boundary);
      if (fixture.path) setFixturePath(body, fixture.path, fixture.value);
      if (fixture.delete_path) deleteFixturePath(body, fixture.delete_path);
      applyStructuralMutation(body, boundary, fixture.mutation);
      const envelope = corpusEnvelope(boundary, body);
      if (fixture.envelope_path) setFixturePath(envelope, fixture.envelope_path, fixture.envelope_value);
      if (fixture.delete_envelope_path) deleteFixturePath(envelope, fixture.delete_envelope_path);
      if (fixture.mutation === "pad_signature") envelope.signature = `${String(envelope.signature)}=`;
      if (fixture.mutation === "noncanonical_signature") envelope.signature = makeNonCanonicalEd25519Signature(String(envelope.signature));
      if (fixture.mutation === "short_signature") envelope.signature = "AA";
      if (fixture.mutation === "zero_signature") envelope.signature = toBase64url(new Uint8Array(64));

      const result = executeCorpusOperation(fixture, boundary, body, envelope);
      expect(result.ok ? "accept" : result.reason, fixture.name).toBe(fixture.verdict);
    }

    for (const fixture of corpus.raw_adversarial) {
      consumedCorpusRows.raw_adversarial.add(fixture.name);
      const result = fixture.operation === "parse_spdx"
        ? parseSpdxExpression(fixture.text)
        : fixture.operation === "parse_catalog_json"
          ? parseCatalogJson(
            fixture.text,
            fixture.max_bytes ?? CATALOG_SIGNING_BODY_MAX_BYTES,
            parseCatalogBodyV3,
          )
          : (() => {
            const exhaustive: never = fixture.operation;
            throw new Error(`unknown raw operation: ${String(exhaustive)}`);
          })();
      expect(result.ok ? "accept" : result.reason, fixture.name).toBe(fixture.verdict);
    }
  });

  it("binds principals and validates a fortress-bound independent overlay union", () => {
    const catalogEnvelope = { body: golden.body, signature: golden.signature, signing_key_id: "cat-epoch-1" };
    expect(verifyAndParseSignedCatalogV3(catalogEnvelope, COMPILED_CATALOG_KEYRING)).toEqual({ ok: false, reason: "bad_signature" });
    expect(verifyAndParseSignedCatalogV3({ ...catalogEnvelope, signing_key_id: "cat-epoch-2" }, TEST_CATALOG_KEYRING)).toEqual({ ok: false, reason: "unknown_signing_key" });
    const rotatedKeyring: readonly CatalogKeyEpoch[] = [
      { ...TEST_CATALOG_KEYRING[0]!, status: "retired", max_catalog_version: 1, max_index_version: 1 },
      { ...COMPILED_CATALOG_KEYRING[0]!, epoch: 2, signing_key_id: "cat-epoch-2", min_catalog_version: 2, min_index_version: 2 },
    ];
    expect(verifyAndParseSignedCatalogV3(catalogEnvelope, rotatedKeyring).ok).toBe(true);
    const revokedKeyring = [{ ...rotatedKeyring[0]!, status: "revoked" as const }, rotatedKeyring[1]!] as const;
    expect(verifyAndParseSignedCatalogV3(catalogEnvelope, revokedKeyring)).toEqual({ ok: false, reason: "signing_key_revoked" });
    expect(verifyAndParseSignedCatalogV3({ ...catalogEnvelope, body: { ...golden.body, catalog_version: 2, previous_catalog_body_sha256: "b".repeat(64) } }, rotatedKeyring)).toEqual({ ok: false, reason: "signing_key_out_of_range" });

    const overlayFixture = corpusBoundary("overlay-body-and-envelope");
    const overlay = corpusBody(overlayFixture) as OverlayBodyV1;
    const overlayEnvelope = corpusEnvelope(overlayFixture, structuredClone(overlay));
    expect(verifyAndParseSignedOverlayV1(overlayEnvelope, fromBase64urlStrict(COMPILED_CATALOG_KEYRING[0]!.pubkey))).toEqual({ ok: false, reason: "unknown_signing_key" });
    const smallOrderKey = new Uint8Array(32); smallOrderKey[0] = 1;
    const smallOrderId = toBase64url(createHash("sha256").update(smallOrderKey).digest());
    expect(verifyAndParseSignedOverlayV1({ ...overlayEnvelope, signer_key_id: smallOrderId }, smallOrderKey)).toEqual({ ok: false, reason: "bad_signature" });
    const expectedBindingId = overlay.overlay_binding_id;
    const verifiedCatalog = verifyAndParseSignedCatalogV3(catalogEnvelope, TEST_CATALOG_KEYRING);
    const verifiedOverlay = verifyAndParseSignedOverlayV1(overlayEnvelope, fromBase64urlStrict(corpus.test_public_key));
    if (!verifiedCatalog.ok || !verifiedOverlay.ok) throw new Error("signed combination fixtures must verify");
    expect(deriveCatalogKeyringSha256(TEST_CATALOG_KEYRING)).toEqual({
      ok: true,
      value: TEST_CATALOG_KEYRING_SHA256,
    });
    expect(validateTestCombination(verifiedCatalog.value, verifiedOverlay.value.body, expectedBindingId, 0)).toEqual({ ok: true, value: true });
    expect(validateTestCombination(
      verifiedCatalog.value,
      verifiedOverlay.value,
      expectedBindingId,
      0,
      "f".repeat(64),
    )).toEqual({ ok: false, reason: "catalog_trust_root_mismatch" });
    expect(validateTestCombination(
      verifiedCatalog.value,
      verifiedOverlay.value,
      expectedBindingId,
      0,
      TEST_CATALOG_KEYRING_SHA256,
      toBase64url(createHash("sha256").update(fromBase64urlStrict(COMPILED_CATALOG_KEYRING[0]!.pubkey)).digest()),
    )).toEqual({ ok: false, reason: "overlay_signer_mismatch" });
    // Structural parsing is never sufficient authority for combination.
    expect(validateTestCombination(golden.body, overlay, expectedBindingId, 0)).toEqual({ ok: false, reason: "unauthenticated_input" });
    expect(validateTestCombination(structuredClone(verifiedCatalog.value.body), verifiedOverlay.value, expectedBindingId, 0)).toEqual({ ok: false, reason: "unauthenticated_input" });
    const reboundOverlay = structuredClone(overlay) as MutableDeep<OverlayBodyV1>; reboundOverlay.overlay_binding_id = "a".repeat(32);
    const verifiedRebound = verifyLocalOverlay(reboundOverlay);
    if (!verifiedRebound.ok) throw new Error("rebound overlay must verify");
    expect(validateTestCombination(
      verifiedCatalog.value.body,
      verifiedRebound.value,
      expectedBindingId,
      0,
      TEST_CATALOG_KEYRING_SHA256,
      localOverlaySignerKeyId(),
    )).toEqual({ ok: false, reason: "overlay_binding_mismatch" });
    const escalatedOverlay = structuredClone(overlay) as MutableDeep<OverlayBodyV1>;
    escalatedOverlay.entries[0]!.assurance = "light";
    escalatedOverlay.entries[0]!.surface_authorization = ["sentinel-scoring"];
    const verifiedEscalated = verifyLocalOverlay(escalatedOverlay);
    if (!verifiedEscalated.ok) throw new Error("escalated overlay must verify");
    expect(validateTestCombination(
      verifiedCatalog.value.body,
      verifiedEscalated.value.body,
      expectedBindingId,
      0,
      TEST_CATALOG_KEYRING_SHA256,
      localOverlaySignerKeyId(),
    )).toEqual({ ok: false, reason: "overlay_escalation" });
    expect(validateTestCombination(verifiedCatalog.value, verifiedOverlay.value, expectedBindingId, 1)).toEqual({ ok: false, reason: "overlay_rollback" });

    const modelIdCollision = structuredClone(overlay) as MutableDeep<OverlayBodyV1>;
    modelIdCollision.entries[0]!.model_id = golden.body.models[0]!.model_id;
    const verifiedModelCollision = verifyLocalOverlay(modelIdCollision);
    if (!verifiedModelCollision.ok) throw new Error("collision overlay must verify");
    expect(validateTestCombination(
      verifiedCatalog.value,
      verifiedModelCollision.value,
      expectedBindingId,
      0,
      TEST_CATALOG_KEYRING_SHA256,
      localOverlaySignerKeyId(),
    )).toEqual({ ok: false, reason: "overlay_collision" });
    const identityAndRuntimeTagCollision = structuredClone(overlay) as MutableDeep<OverlayBodyV1>;
    Object.assign(identityAndRuntimeTagCollision.entries[0]!.identity, structuredClone(golden.body.models[0]!.identity));
    const verifiedIdentityCollision = verifyLocalOverlay(identityAndRuntimeTagCollision);
    if (!verifiedIdentityCollision.ok) throw new Error("identity collision overlay must verify");
    expect(validateTestCombination(
      verifiedCatalog.value,
      verifiedIdentityCollision.value,
      expectedBindingId,
      0,
      TEST_CATALOG_KEYRING_SHA256,
      localOverlaySignerKeyId(),
    )).toEqual({ ok: false, reason: "overlay_collision" });
    // The same complete-union validation is used whether an overlay is added
    // after a catalog or a new catalog is evaluated against a held overlay.
    const laterCatalog = structuredClone(golden.body);
    laterCatalog.models[0]!.model_id = overlay.entries[0]!.model_id;
    const verifiedLaterCatalog = verifyLocalCatalog(laterCatalog);
    if (!verifiedLaterCatalog.ok) throw new Error("later catalog must verify");
    expect(validateTestCombination(
      verifiedLaterCatalog.value.body,
      verifiedOverlay.value,
      expectedBindingId,
      0,
      localCatalogKeyringSha256(),
      TEST_OVERLAY_SIGNER_KEY_ID,
    )).toEqual({ ok: false, reason: "overlay_collision" });

    expect(validateTestCombination(null, verifiedOverlay.value, expectedBindingId, 0)).toEqual({ ok: false, reason: "unauthenticated_input" });
    expect(validateTestCombination(verifiedCatalog.value, null, expectedBindingId, 0)).toEqual({ ok: false, reason: "unauthenticated_input" });
    expect(validateTestCombination(verifiedCatalog.value, verifiedOverlay.value, undefined, 0)).toEqual({ ok: false, reason: "invalid_value" });
    expect(validateTestCombination(verifiedCatalog.value, verifiedOverlay.value, expectedBindingId, undefined)).toEqual({ ok: false, reason: "invalid_value" });
    let combinationProxyCalls = 0;
    const hostile = new Proxy({}, {
      get: () => { combinationProxyCalls++; throw new Error("hostile property get"); },
      getOwnPropertyDescriptor: () => { combinationProxyCalls++; throw new Error("hostile property descriptor"); },
      ownKeys: () => { combinationProxyCalls++; throw new Error("hostile ownKeys"); },
    });
    expect(validateTestCombination(hostile, verifiedOverlay.value, expectedBindingId, 0)).toEqual({ ok: false, reason: "unauthenticated_input" });
    expect(combinationProxyCalls).toBe(0);
  });

  it("labels retained continuity as untrusted observation data until S2", () => {
    const catalogEnvelope = { body: golden.body, signature: golden.signature, signing_key_id: "cat-epoch-1" };
    const catalogObservation = {
      status: "observed",
      last_admitted_envelope: catalogEnvelope,
      last_admitted_catalog_version: 1,
      last_admitted_body_sha256: golden.canonical_body_sha256,
      last_admitted_previous_body_sha256: null,
      catalog_key_epoch: 1,
      catalog_version_floor: 1,
    };
    expect(parseUntrustedCatalogContinuityObservationV3(catalogObservation).ok).toBe(true);
    expect(parseUntrustedCatalogContinuityObservationV3({ ...catalogObservation, status: "trusted" })).toEqual({ ok: false, reason: "invalid_value" });

    const indexFixture = corpusBoundary("catalog-index-body-and-envelope");
    const indexBody = corpusBody(indexFixture);
    const indexObservation = {
      index_continuity_status: "observed",
      index_envelope: corpusEnvelope(indexFixture, indexBody),
      index_version_floor: 1,
      index_body_sha256: indexFixture.body_sha256,
      index_key_epoch: 1,
    };
    expect(parseUntrustedCatalogIndexContinuityObservationV1(indexObservation).ok).toBe(true);
    expect(parseUntrustedCatalogIndexContinuityObservationV1({ ...indexObservation, index_continuity_status: "trusted" })).toEqual({ ok: false, reason: "invalid_value" });
  });

  it("rejects duplicate keys, non-canonical numbers, array order, and signature encodings", () => {
    expect(parseCatalogJson('{"schema":"x","schema":"y"}', CATALOG_SIGNING_BODY_MAX_BYTES, parseCatalogBodyV3)).toEqual({ ok: false, reason: "duplicate_key" });
    const exponent = JSON.stringify(golden.body).replace('"catalog_version":1', '"catalog_version":1e0');
    expect(parseCatalogJson(exponent, CATALOG_SIGNING_BODY_MAX_BYTES, parseCatalogBodyV3)).toEqual({ ok: false, reason: "invalid_value" });
    const negative = JSON.stringify(golden.body).replace('"catalog_version":1', '"catalog_version":-1');
    expect(parseCatalogJson(negative, CATALOG_SIGNING_BODY_MAX_BYTES, parseCatalogBodyV3)).toEqual({ ok: false, reason: "invalid_value" });
    expect(parseCatalogJson(JSON.stringify(golden.body), 0, parseCatalogBodyV3)).toEqual({ ok: false, reason: "invalid_value" });
    expect(parseCatalogJson(JSON.stringify(golden.body), Number.NaN, parseCatalogBodyV3)).toEqual({ ok: false, reason: "invalid_value" });
    const catalogEnvelope = { body: golden.body, signature: golden.signature, signing_key_id: "cat-epoch-1" };
    const oversizedSignature = "A".repeat(1_000_000);
    expect(verifyAndParseSignedCatalogV3({ ...catalogEnvelope, signature: oversizedSignature }, TEST_CATALOG_KEYRING)).toEqual({ ok: false, reason: "bad_signature_length" });
    const indexFixture = corpusBoundary("catalog-index-body-and-envelope");
    const indexEnvelope = corpusEnvelope(indexFixture, corpusBody(indexFixture));
    expect(verifyAndParseSignedCatalogIndexSegmentV1({ ...indexEnvelope, signature: oversizedSignature }, TEST_CATALOG_KEYRING)).toEqual({ ok: false, reason: "bad_signature_length" });
    const overlayFixture = corpusBoundary("overlay-body-and-envelope");
    const overlayEnvelope = corpusEnvelope(overlayFixture, corpusBody(overlayFixture));
    expect(verifyAndParseSignedOverlayV1({ ...overlayEnvelope, signature: oversizedSignature }, fromBase64urlStrict(corpus.test_public_key))).toEqual({ ok: false, reason: "bad_signature_length" });

    const preimage = buildDomainSignaturePreimage(CATALOG_V3_DOMAIN, golden.body);
    const identityR = makeIdentityREd25519Signature(preimage);
    expect(verifyAndParseSignedCatalogV3(
      { ...catalogEnvelope, signature: identityR.signature },
      keyringWithPublicKey(identityR.publicKey),
    )).toEqual({ ok: false, reason: "bad_signature" });
    expect(verifyAndParseSignedCatalogV3({ ...catalogEnvelope, signature: `${golden.signature}=` }, TEST_CATALOG_KEYRING)).toEqual({ ok: false, reason: "bad_signature_length" });
    expect(golden.signature.endsWith("w")).toBe(true);
    expect(verifyAndParseSignedCatalogV3(
      { ...catalogEnvelope, signature: `${golden.signature.slice(0, -1)}x` },
      TEST_CATALOG_KEYRING,
    )).toEqual({ ok: false, reason: "bad_signature_encoding" });
    expect(verifyAndParseSignedCatalogV3({ ...catalogEnvelope, signature: "AA" }, TEST_CATALOG_KEYRING)).toEqual({ ok: false, reason: "bad_signature_length" });
    expect(verifyAndParseSignedCatalogV3({ ...catalogEnvelope, signature: makeNonCanonicalEd25519Signature(golden.signature) }, TEST_CATALOG_KEYRING)).toEqual({ ok: false, reason: "bad_signature" });
    const unsortedOverlayFixture = corpusBoundary("overlay-body-and-envelope");
    const unsortedOverlay = corpusBody(unsortedOverlayFixture) as MutableDeep<OverlayBodyV1>;
    unsortedOverlay.entries[0]!.surface_authorization = ["privacy-filter-tier-2", "sentinel-scoring"];
    expect(parseCatalogJson(JSON.stringify(unsortedOverlay), 64 * 1_024, parseOverlayBodyV1)).toEqual({ ok: false, reason: "invalid_order" });
    const unicodeDescription = structuredClone(golden.body);
    unicodeDescription.tiers.tiers.baseline.description = "Cafe\u0301";
    expect(parseCatalogJson(JSON.stringify(unicodeDescription), CATALOG_SIGNING_BODY_MAX_BYTES, parseCatalogBodyV3)).toEqual({ ok: false, reason: "invalid_value" });
    const redefinedCompiledTier = structuredClone(golden.body);
    redefinedCompiledTier.tiers.tiers.baseline.description = "Operator-defined baseline";
    expect(parseCatalogBodyV3(redefinedCompiledTier)).toEqual({ ok: false, reason: "invalid_value" });
    const zeroPreviousDigest = { ...structuredClone(golden.body), catalog_version: 2, previous_catalog_body_sha256: "0".repeat(64) };
    expect(parseCatalogBodyV3(zeroPreviousDigest)).toEqual({ ok: false, reason: "invalid_value" });
    const badEvidenceUrl = structuredClone(golden.body);
    badEvidenceUrl.models[0]!.license.source_url = "https://user@example.com/license";
    expect(parseCatalogBodyV3(badEvidenceUrl)).toEqual({ ok: false, reason: "invalid_value" });
    for (const sourceUrl of [
      "https://127.0.0.1/license",
      "https://127.1/license",
      "https://0x7f000001/license",
      "https://169.254.1.1/license",
      "https://xn--bcher-kva.example/license",
      "https://-bad.example/license",
      "https://bad-.example/license",
      "https://example..com/license",
      "https://example.com/license%00evidence",
      "https://example.com/license%1Fevidence",
      "https://example.com/%2fsecret",
      "https://example.com/license%7Fevidence",
      "https://example.com:443/license",
      "https://example.com:0444/license",
      "https://example.com/%FF",
    ]) {
      const invalidSource = structuredClone(golden.body);
      invalidSource.models[0]!.license.source_url = sourceUrl;
      expect(parseCatalogBodyV3(invalidSource), sourceUrl).toEqual({ ok: false, reason: "invalid_value" });
    }
    expect(parseCatalogJson(`{"padding":"${"a".repeat(70_000)}"}`, Number.MAX_SAFE_INTEGER, parseCatalogBodyV3)).toEqual({ ok: false, reason: "manifest_too_large" });
    expect(() => parseCatalogJson("{}", 1024, () => { throw new Error("implementation defect"); })).toThrow("implementation defect");

    for (const malformedBody of [
      { value: undefined },
      { value: 1.5 },
      new Array(2),
    ]) {
      expect(() => canonicalizeJson(malformedBody)).toThrow();
    }
    let nested: unknown = null;
    for (let depth = 0; depth < 66; depth++) nested = [nested];
    expect(() => canonicalizeJson(nested)).toThrow();

    const compensatedHole = new Array(2) as unknown[] & { extra?: string };
    compensatedHole[1] = "x";
    compensatedHole.extra = "enumerable key masks the missing index by count";
    expect(() => canonicalizeJson(compensatedHole)).toThrow();

    const invertedTiers = structuredClone(golden.body);
    invertedTiers.tiers.tiers.baseline.min_ram_gib = 64;
    invertedTiers.tiers.tiers.mid.min_ram_gib = 16;
    invertedTiers.tiers.tiers.pro.min_ram_gib = 32;
    expect(parseCatalogBodyV3(invertedTiers)).toEqual({ ok: false, reason: "invalid_order" });

    const equalTiers = structuredClone(golden.body);
    equalTiers.tiers.tiers.baseline.min_ram_gib = 16;
    equalTiers.tiers.tiers.mid.min_ram_gib = 16;
    equalTiers.tiers.tiers.pro.min_ram_gib = 32;
    expect(parseCatalogBodyV3(equalTiers)).toEqual({ ok: false, reason: "invalid_order" });

    const indexBody = corpusBody(indexFixture) as Record<string, unknown>;
    expect(verifyLocalIndex(indexBody).ok).toBe(true);
    const unauthenticatedUnknownEpoch = structuredClone(indexBody) as { entries: Array<Record<string, unknown>> };
    unauthenticatedUnknownEpoch.entries[0]!.catalog_key_epoch = 9;
    expect(verifyAndParseSignedCatalogIndexSegmentV1(
      corpusEnvelope(indexFixture, unauthenticatedUnknownEpoch),
      TEST_CATALOG_KEYRING,
    )).toEqual({ ok: false, reason: "bad_signature" });
    const impossibleSegment = structuredClone(indexBody);
    impossibleSegment.segment_number = 2;
    expect(parseCatalogIndexBodyV1(impossibleSegment)).toEqual({ ok: false, reason: "invalid_value" });
    const truncatedSegment = structuredClone(indexBody);
    truncatedSegment.index_version = 2;
    truncatedSegment.highest_catalog_version = 1;
    truncatedSegment.previous_index_body_sha256 = "a".repeat(64);
    expect(parseCatalogIndexBodyV1(truncatedSegment)).toEqual({ ok: false, reason: "invalid_value" });
    const mismatchedBase = structuredClone(indexBody);
    mismatchedBase.index_version = 2;
    mismatchedBase.highest_catalog_version = 2;
    mismatchedBase.segment_base_index_version = 2;
    expect(parseCatalogIndexBodyV1(mismatchedBase)).toEqual({ ok: false, reason: "invalid_value" });

    for (const field of ["catalog_release_id", "catalog_asset_id", "envelope_sha256", "body_sha256"] as const) {
      const duplicate = structuredClone(indexBody) as {
        index_version: number;
        previous_index_body_sha256: string | null;
        segment_number: number;
        segment_base_index_version: number;
        first_catalog_version: number;
        highest_catalog_version: number;
        entries: Array<Record<string, unknown>>;
      };
      duplicate.index_version = 2;
      duplicate.previous_index_body_sha256 = "a".repeat(64);
      duplicate.highest_catalog_version = 2;
      const second: Record<string, unknown> = {
        ...structuredClone(duplicate.entries[0]!),
        catalog_version: 2,
        catalog_release_id: 1002,
        catalog_asset_id: 2002,
        envelope_sha256: "5".repeat(64),
        body_sha256: "6".repeat(64),
      };
      second[field] = duplicate.entries[0]![field];
      duplicate.entries.push(second);
      expect(parseCatalogIndexBodyV1(duplicate), field).toEqual({ ok: false, reason: "duplicate_entry" });
    }
    const selfCollidingDigest = structuredClone(indexBody) as { entries: Array<Record<string, unknown>> };
    selfCollidingDigest.entries[0]!.body_sha256 = selfCollidingDigest.entries[0]!.envelope_sha256;
    expect(parseCatalogIndexBodyV1(selfCollidingDigest)).toEqual({ ok: false, reason: "duplicate_entry" });

    const epochBoundIndex = structuredClone(indexBody) as {
      index_version: number;
      previous_index_body_sha256: string | null;
      segment_number: number;
      segment_base_index_version: number;
      first_catalog_version: number;
      highest_catalog_version: number;
      entries: Array<Record<string, unknown>>;
    };
    epochBoundIndex.index_version = 2;
    epochBoundIndex.previous_index_body_sha256 = "a".repeat(64);
    epochBoundIndex.segment_number = 2;
    epochBoundIndex.segment_base_index_version = 2;
    epochBoundIndex.first_catalog_version = 2;
    epochBoundIndex.highest_catalog_version = 2;
    epochBoundIndex.entries[0]!.catalog_version = 2;
    epochBoundIndex.entries[0]!.catalog_key_epoch = 1;
    expect(verifyRotatedIndex(epochBoundIndex, twoEpochKeyring("retired"))).toEqual({
      ok: false,
      reason: "signing_key_out_of_range",
    });
    expect(verifyRotatedIndex(epochBoundIndex, twoEpochKeyring("revoked"))).toEqual({
      ok: false,
      reason: "signing_key_revoked",
    });
  });

  it("offers strict string-taking verification for every signed wire envelope", () => {
    const catalogEnvelope = {
      body: golden.body,
      signature: golden.signature,
      signing_key_id: "cat-epoch-1",
    };
    expect(verifyAndParseSignedCatalogJsonV3(
      JSON.stringify(catalogEnvelope),
      TEST_CATALOG_KEYRING,
    ).ok).toBe(true);
    const duplicateCatalogBody = JSON.stringify(catalogEnvelope)
      .replace('{"body":', '{"body":null,"body":');
    expect(verifyAndParseSignedCatalogJsonV3(
      duplicateCatalogBody,
      TEST_CATALOG_KEYRING,
    )).toEqual({ ok: false, reason: "duplicate_key" });
    expect(verifyAndParseSignedCatalogJsonV3(
      catalogEnvelope,
      TEST_CATALOG_KEYRING,
    )).toEqual({ ok: false, reason: "invalid_type" });

    const indexFixture = corpusBoundary("catalog-index-body-and-envelope");
    const indexEnvelope = corpusEnvelope(indexFixture, corpusBody(indexFixture));
    expect(verifyAndParseSignedCatalogIndexJsonV1(
      JSON.stringify(indexEnvelope),
      TEST_CATALOG_KEYRING,
    ).ok).toBe(true);
    expect(verifyAndParseSignedCatalogIndexJsonV1(
      JSON.stringify(indexEnvelope).replace('{"body":', '{"body":null,"body":'),
      TEST_CATALOG_KEYRING,
    )).toEqual({ ok: false, reason: "duplicate_key" });

    const overlayFixture = corpusBoundary("overlay-body-and-envelope");
    const overlayEnvelope = corpusEnvelope(overlayFixture, corpusBody(overlayFixture));
    expect(verifyAndParseSignedOverlayJsonV1(
      JSON.stringify(overlayEnvelope),
      fromBase64urlStrict(corpus.test_public_key),
    ).ok).toBe(true);
    expect(verifyAndParseSignedOverlayJsonV1(
      JSON.stringify(overlayEnvelope).replace('{"body":', '{"body":null,"body":'),
      fromBase64urlStrict(corpus.test_public_key),
    )).toEqual({ ok: false, reason: "duplicate_key" });

    for (const boundary of corpus.boundaries) {
      const body = corpusBody(boundary);
      const parsed = boundary.domain === CATALOG_V3_DOMAIN
        ? parseCatalogBodyV3(body)
        : boundary.domain === CATALOG_INDEX_V1_DOMAIN
          ? parseCatalogIndexBodyV1(body)
          : parseOverlayBodyV1(body);
      if (!parsed.ok) throw new Error(`${boundary.name} must parse`);
      expect(canonicalizeJson(parsed.value), boundary.name).toBe(canonicalizeJson(body));
    }
  });

  it("executes the generated signing-size boundaries from the parity corpus", () => {
    for (const fixture of corpus.generated_size_cases) {
      consumedCorpusRows.generated_size_cases.add(fixture.name);
      expect(fixture.measurement, fixture.name).toBe("catalog_domain_preimage_bytes");
      const body = buildCatalogCapBody(fixture.preimage_bytes);
      expect(buildDomainSignaturePreimage(CATALOG_V3_DOMAIN, body), fixture.name).toHaveLength(fixture.preimage_bytes);
      const parsed = parseCatalogJson(JSON.stringify(body), 64 * 1_024, parseCatalogBodyV3);
      expect(parsed.ok ? "accept" : parsed.reason, fixture.name).toBe(fixture.verdict);
    }
  });

  it("enforces exact per-domain signature-preimage byte caps", () => {
    for (const [domain, limit] of [
      [CATALOG_V3_DOMAIN, CATALOG_SIGNING_BODY_MAX_BYTES],
      [CATALOG_INDEX_V1_DOMAIN, CATALOG_INDEX_SIGNING_BODY_MAX_BYTES],
      [OVERLAY_V1_DOMAIN, OVERLAY_SIGNING_BODY_MAX_BYTES],
    ] as const) {
      const base = buildDomainSignaturePreimage(domain, { padding: "" }).length;
      const atLimit = { padding: "a".repeat(limit - base) };
      expect(buildDomainSignaturePreimage(domain, atLimit), domain).toHaveLength(limit);
      expect(isDomainSignaturePreimageWithinLimit(domain, atLimit), domain).toBe(true);
      expect(isDomainSignaturePreimageWithinLimit(domain, { padding: `${atLimit.padding}a` }), domain).toBe(false);
    }
    expect(isDomainSignaturePreimageWithinLimit("unknown.domain", {})).toBe(false);
    expect(isDomainSignaturePreimageWithinLimit(CATALOG_V3_DOMAIN, new Proxy({}, {
      ownKeys() { throw new Error("hostile preimage"); },
    }))).toBe(false);
  });

  it("pins the golden fixture itself against accidental byte edits", () => {
    const fixture = readFileSync(fileURLToPath(new URL("../fixtures/catalog-v3/catalog-body-golden.json", import.meta.url)));
    expect(createHash("sha256").update(fixture).digest("hex")).toBe("c90d86729aa42a8e0e997fbdbcc9767f55c1d26d02f5b9cbde3fb4ba6efbbc93");
    const corpusFixture = readFileSync(fileURLToPath(new URL("../fixtures/catalog-v3/wire-boundaries-golden.json", import.meta.url)));
    expect(createHash("sha256").update(corpusFixture).digest("hex")).toBe("dc005d59de4fdbf4aff2b1a1b7c21e0c28d9606f0e3e6289ed24f9a658dbc767");
    const verifier = readFileSync(fileURLToPath(new URL("../fixtures/catalog-v3/verify-golden.py", import.meta.url)));
    expect(createHash("sha256").update(verifier).digest("hex")).toBe("e8ca6c01aa3d212ac5ab1ac939fb990a49f9ef7188eeed4e625337e338f7052c");
  });

  it("accounts for every portable-corpus section and row exactly once", () => {
    expect(Object.keys(wireGolden).sort()).toEqual([
      "boundaries", "contract_cases", "derived_test_signer_key_id", "generated_size_cases",
      "raw_adversarial", "schema", "spdx", "test_catalog_keyring", "test_public_key",
    ]);
    expect(new Set(corpus.boundaries.map((row) => row.name)).size).toBe(corpus.boundaries.length);
    expect(new Set(corpus.spdx.map((row) => row.source)).size).toBe(corpus.spdx.length);
    const expectedRows = {
      boundaries: corpus.boundaries.map((row) => row.name),
      spdx: corpus.spdx.map((row) => row.source),
      contract_cases: corpus.contract_cases.map((row) => row.name),
      generated_size_cases: corpus.generated_size_cases.map((row) => row.name),
      raw_adversarial: corpus.raw_adversarial.map((row) => row.name),
    };
    for (const section of Object.keys(expectedRows) as Array<keyof typeof expectedRows>) {
      expect(new Set(expectedRows[section]).size, section).toBe(expectedRows[section].length);
      expect(
        createHash("sha256").update(expectedRows[section].join("\n")).digest("hex"),
        `${section} ordered row inventory`,
      ).toBe(EXPECTED_CORPUS_ROW_DIGESTS[section]);
      expect([...consumedCorpusRows[section]].sort(), section).toEqual([...expectedRows[section]].sort());
    }
  });
});
