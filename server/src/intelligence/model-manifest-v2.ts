/**
 * Q5A: corrected, inert model-load-integrity contract.
 *
 * This module is deliberately pure. It parses and authenticates V2 catalog
 * bytes, derives Ollama identities/paths, and validates a persisted armed
 * record supplied by a caller. It performs no fetch, host read, state write,
 * selector mutation, model pull, or activation.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { isAbsolute, posix } from "node:path";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../core/crypto-suite-registry.js";
import { fromBase64urlStrict, stringToBytes } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import { parseIsoInstantWithOffset } from "../core/time.js";
import { canonicalJson } from "../v1/operator-signed.js";
import { SubstrateError } from "../substrate/errors.js";
import { parseStrictJson } from "../substrate/strict-json.js";
import {
  MODEL_LICENSE_REDISTRIBUTION,
  MODEL_MANIFEST_MAX_JSON_CHARS,
  MODEL_MANIFEST_MAX_MODELS,
  MODEL_MANIFEST_MAX_MODELS_PER_TIER,
  MODEL_MANIFEST_MAX_PARAMS_B,
  MODEL_MANIFEST_MAX_STRING_CHARS,
  MODEL_MANIFEST_MAX_URL_CHARS,
  MODEL_MANIFEST_MAX_VERSION,
  MODEL_MANIFEST_MIN_PARAMS_B,
  MODEL_MANIFEST_TIERS,
  PINNED_MODEL_CATALOG_ROOT_PUBLIC_KEY_B64URL,
  type ModelLicenseMetadata,
  type ModelLicenseRedistribution,
  type ModelManifestTier,
} from "./model-manifest.js";
import { SURFACES, type Surface } from "./surfaces.js";

export const MODEL_MANIFEST_V2_DOMAIN = "sanctuary.model-manifest.v2";
export const MODEL_MANIFEST_V2_DELIMITER = "\n";
export const MODEL_MANIFEST_V2_SCHEMA_VERSION = 2 as const;
export const MODEL_MANIFEST_V2_REGISTRY = "registry.ollama.ai" as const;
/**
 * V2 bodies are signed by the dedicated model-catalog root, never by the
 * release-signing key (owner ruling 2, 2026-09-03). The runtime decodes this
 * through `loadPinnedModelManifestKey` in model-manifest.ts; this alias exists
 * so the V2 contract names its own trust root at its own surface.
 */
export const PINNED_MODEL_MANIFEST_V2_SIGNING_PUBLIC_KEY_B64URL =
  PINNED_MODEL_CATALOG_ROOT_PUBLIC_KEY_B64URL;

export const MODEL_LOAD_INTEGRITY_ASSURANCES = ["light", "immune"] as const;
export type ModelLoadIntegrityAssurance =
  (typeof MODEL_LOAD_INTEGRITY_ASSURANCES)[number];

export const IMMUNE_MODEL_LOAD_SURFACES = [
  "sentinel-scoring",
  "privacy-filter-tier-2",
] as const satisfies readonly Surface[];

/** Design section 9.1 is a closed audit/status reason taxonomy. */
export const MODEL_LOAD_INTEGRITY_FAILURE_REASONS = [
  "integrity_state_absent",
  "integrity_state_invalid",
  "manifest_signature_invalid",
  "manifest_rollback",
  "binding_mismatch",
  "runtime_model_absent",
  "runtime_manifest_digest_invalid",
  "runtime_manifest_digest_mismatch",
  "model_root_invalid",
  "path_escape",
  "symlink_refused",
  "disk_manifest_invalid",
  "disk_manifest_digest_mismatch",
  "descriptor_bounds_exceeded",
  "layer_missing",
  "layer_size_mismatch",
  "layer_digest_mismatch",
  "unstable_file",
  "integrity_io_unavailable",
  "immune_platform_unsupported",
] as const;
export type ModelLoadIntegrityFailureReason =
  (typeof MODEL_LOAD_INTEGRITY_FAILURE_REASONS)[number];

const IMMUNE_SURFACE_SET = new Set<Surface>(IMMUNE_MODEL_LOAD_SURFACES);
// The `{0,63}` bound must match OLLAMA_IDENTITY_COMPONENT_MAX_CHARS in runtime-light-verifier.ts and immune-disk-verifier.ts.
const IDENTITY_COMPONENT = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MODEL_ID = /^[a-z0-9][a-z0-9._-]{0,255}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const ALL_ZERO_SHA256 = "0".repeat(64);

export interface SignedOllamaIdentityV2 {
  registry: typeof MODEL_MANIFEST_V2_REGISTRY;
  namespace: string;
  model: string;
  tag: string;
  ollama_manifest_sha256: string;
}

export interface ModelManifestModelV2 {
  model_id: string;
  model_name: string;
  model_version: string;
  provider: string;
  runtime: "ollama";
  ollama_identity: SignedOllamaIdentityV2;
  params_b: number;
  license: ModelLicenseMetadata;
  open_weights: boolean;
  open_source: boolean;
}

export type ModelManifestTierBundlesV2 = Record<
  ModelManifestTier,
  readonly string[]
>;

export type ModelManifestSurfaceDefaultsV2 = Record<
  ModelManifestTier,
  Record<Surface, string | null>
>;

export interface ModelManifestBodyV2 {
  schema_version: typeof MODEL_MANIFEST_V2_SCHEMA_VERSION;
  manifest_version: number;
  models: Record<string, ModelManifestModelV2>;
  tiers: ModelManifestTierBundlesV2;
  surface_defaults: ModelManifestSurfaceDefaultsV2;
}

export interface SignedModelManifestV2 {
  body: ModelManifestBodyV2;
  signature: string;
}

export interface VerifiedLocalBindingV2 {
  model_id: string;
  runtime_tag: string;
  ollama_identity: SignedOllamaIdentityV2;
  assurance: ModelLoadIntegrityAssurance;
  manifest_version: number;
}

export interface LocalIntegrityStateV2 {
  state: "armed";
  schema_version: typeof MODEL_MANIFEST_V2_SCHEMA_VERSION;
  manifest_version_floor: number;
  signed_manifest: SignedModelManifestV2;
  signed_body_sha256: string;
  ollama_models_root: string;
  bindings: Partial<Record<Surface, VerifiedLocalBindingV2>>;
  committed_at: string;
}

export type ModelManifestV2RefusalReason =
  | "absent"
  | "manifest_too_large"
  | "malformed_json"
  | "duplicate_key"
  | "prototype_key"
  | "missing_key"
  | "unknown_key"
  | "invalid_type"
  | "invalid_value"
  | "collection_too_large"
  | "invalid_reference"
  | "license_contradiction"
  | "bad_signature_encoding"
  | "bad_signature_length"
  | "zero_signature"
  | "bad_signature"
  | "bad_pinned_key_length"
  | "zero_pinned_key"
  | "invalid_version_floor"
  | "rollback"
  | "downgrade"
  | "integrity_state_invalid"
  | "binding_mismatch"
  | "model_root_invalid";

type ParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: ModelManifestV2RefusalReason };

export type ModelManifestV2VerificationResult =
  | { ok: true; manifest: SignedModelManifestV2; body: ModelManifestBodyV2 }
  | { ok: false; reason: ModelManifestV2RefusalReason };

export type LocalIntegrityStateV2ValidationResult =
  | { ok: true; state: LocalIntegrityStateV2 }
  | { ok: false; reason: ModelManifestV2RefusalReason };

const ENVELOPE_KEYS = ["body", "signature"] as const;
const BODY_KEYS = [
  "schema_version",
  "manifest_version",
  "models",
  "tiers",
  "surface_defaults",
] as const;
const MODEL_KEYS = [
  "model_id",
  "model_name",
  "model_version",
  "provider",
  "runtime",
  "ollama_identity",
  "params_b",
  "license",
  "open_weights",
  "open_source",
] as const;
const IDENTITY_KEYS = [
  "registry",
  "namespace",
  "model",
  "tag",
  "ollama_manifest_sha256",
] as const;
const LICENSE_KEYS = [
  "identifier",
  "name",
  "url",
  "osi_approved",
  "redistribution",
] as const;
const STATE_KEYS = [
  "state",
  "schema_version",
  "manifest_version_floor",
  "signed_manifest",
  "signed_body_sha256",
  "ollama_models_root",
  "bindings",
  "committed_at",
] as const;
const BINDING_KEYS = [
  "model_id",
  "runtime_tag",
  "ollama_identity",
  "assurance",
  "manifest_version",
] as const;

function fail<T>(reason: ModelManifestV2RefusalReason): ParseResult<T> {
  return { ok: false, reason };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function checkExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): ModelManifestV2RefusalReason | null {
  let count = 0;
  const seen = new Set<string>();
  for (const key in value) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    count += 1;
    if (count > expected.length || !expected.includes(key)) return "unknown_key";
    seen.add(key);
  }
  for (const key of expected) {
    if (!seen.has(key)) return "missing_key";
  }
  return null;
}

function boundedString(value: unknown, max = MODEL_MANIFEST_MAX_STRING_CHARS): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > max) return null;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return null;
  }
  return value;
}

function parseLicense(value: unknown): ParseResult<ModelLicenseMetadata> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, LICENSE_KEYS);
  if (keyFailure !== null) return fail(keyFailure);
  const identifier = boundedString(value.identifier);
  const name = boundedString(value.name);
  const urlText = boundedString(value.url, MODEL_MANIFEST_MAX_URL_CHARS);
  if (identifier === null || name === null || urlText === null) return fail("invalid_value");
  try {
    const url = new URL(urlText);
    if (url.protocol !== "https:" || url.username !== "" || url.password !== "") {
      return fail("invalid_value");
    }
  } catch {
    return fail("invalid_value");
  }
  if (typeof value.osi_approved !== "boolean") return fail("invalid_type");
  if (
    typeof value.redistribution !== "string" ||
    !MODEL_LICENSE_REDISTRIBUTION.includes(
      value.redistribution as ModelLicenseRedistribution,
    )
  ) {
    return fail("invalid_value");
  }
  if (
    value.osi_approved &&
    ["unknown", "proprietary"].includes(identifier.toLowerCase())
  ) {
    return fail("license_contradiction");
  }
  return {
    ok: true,
    value: {
      identifier,
      name,
      url: urlText,
      osi_approved: value.osi_approved,
      redistribution: value.redistribution as ModelLicenseRedistribution,
    },
  };
}

function parseOllamaIdentity(value: unknown): ParseResult<SignedOllamaIdentityV2> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, IDENTITY_KEYS);
  if (keyFailure !== null) return fail(keyFailure);
  if (value.registry !== MODEL_MANIFEST_V2_REGISTRY) return fail("invalid_value");
  const namespace = boundedString(value.namespace, 64);
  const model = boundedString(value.model, 64);
  const tag = boundedString(value.tag, 64);
  const digest = boundedString(value.ollama_manifest_sha256, 64);
  if (
    namespace === null || model === null || tag === null || digest === null ||
    !IDENTITY_COMPONENT.test(namespace) || !IDENTITY_COMPONENT.test(model) ||
    !IDENTITY_COMPONENT.test(tag) || !SHA256_HEX.test(digest) ||
    digest === ALL_ZERO_SHA256
  ) {
    return fail("invalid_value");
  }
  return {
    ok: true,
    value: {
      registry: MODEL_MANIFEST_V2_REGISTRY,
      namespace,
      model,
      tag,
      ollama_manifest_sha256: digest,
    },
  };
}

function parseModel(modelId: string, value: unknown): ParseResult<ModelManifestModelV2> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, MODEL_KEYS);
  if (keyFailure !== null) return fail(keyFailure);
  const declaredId = boundedString(value.model_id);
  const modelName = boundedString(value.model_name);
  const modelVersion = boundedString(value.model_version);
  const provider = boundedString(value.provider);
  if (
    declaredId === null || declaredId !== modelId || !MODEL_ID.test(declaredId) ||
    modelName === null || modelVersion === null || provider === null ||
    value.runtime !== "ollama"
  ) {
    return fail("invalid_value");
  }
  if (
    typeof value.params_b !== "number" || !Number.isFinite(value.params_b) ||
    value.params_b < MODEL_MANIFEST_MIN_PARAMS_B ||
    value.params_b > MODEL_MANIFEST_MAX_PARAMS_B
  ) {
    return fail("invalid_value");
  }
  if (typeof value.open_weights !== "boolean" || typeof value.open_source !== "boolean") {
    return fail("invalid_type");
  }
  const identity = parseOllamaIdentity(value.ollama_identity);
  if (!identity.ok) return identity;
  const license = parseLicense(value.license);
  if (!license.ok) return license;
  if (value.open_source && (!value.open_weights || !license.value.osi_approved)) {
    return fail("license_contradiction");
  }
  return {
    ok: true,
    value: {
      model_id: declaredId,
      model_name: modelName,
      model_version: modelVersion,
      provider,
      runtime: "ollama",
      ollama_identity: identity.value,
      params_b: value.params_b,
      license: license.value,
      open_weights: value.open_weights,
      open_source: value.open_source,
    },
  };
}

function parseModels(value: unknown): ParseResult<Record<string, ModelManifestModelV2>> {
  if (!isRecord(value)) return fail("invalid_type");
  const models = Object.create(null) as Record<string, ModelManifestModelV2>;
  const runtimeTagDigests = new Map<string, string>();
  let count = 0;
  for (const modelId in value) {
    if (!Object.prototype.hasOwnProperty.call(value, modelId)) continue;
    count += 1;
    if (count > MODEL_MANIFEST_MAX_MODELS) return fail("collection_too_large");
    if (!MODEL_ID.test(modelId)) return fail("invalid_value");
    const model = parseModel(modelId, value[modelId]);
    if (!model.ok) return model;
    const runtimeTag = deriveOllamaRuntimeTag(model.value.ollama_identity);
    const priorDigest = runtimeTagDigests.get(runtimeTag);
    if (priorDigest !== undefined && priorDigest !== model.value.ollama_identity.ollama_manifest_sha256) {
      return fail("invalid_reference");
    }
    runtimeTagDigests.set(runtimeTag, model.value.ollama_identity.ollama_manifest_sha256);
    models[modelId] = model.value;
  }
  return count === 0 ? fail("invalid_value") : { ok: true, value: models };
}

function parseTiers(
  value: unknown,
  models: Readonly<Record<string, ModelManifestModelV2>>,
): ParseResult<ModelManifestTierBundlesV2> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, MODEL_MANIFEST_TIERS);
  if (keyFailure !== null) return fail(keyFailure);
  const result = Object.create(null) as Record<ModelManifestTier, string[]>;
  const assigned = new Set<string>();
  for (const tier of MODEL_MANIFEST_TIERS) {
    const raw = value[tier];
    if (!Array.isArray(raw)) return fail("invalid_type");
    if (raw.length === 0) return fail("invalid_value");
    if (raw.length > MODEL_MANIFEST_MAX_MODELS_PER_TIER) return fail("collection_too_large");
    const seen = new Set<string>();
    result[tier] = [];
    for (const modelId of raw) {
      if (typeof modelId !== "string" || models[modelId] === undefined || seen.has(modelId)) {
        return fail("invalid_reference");
      }
      seen.add(modelId);
      assigned.add(modelId);
      result[tier].push(modelId);
    }
  }
  for (const modelId in models) {
    if (!assigned.has(modelId)) return fail("invalid_reference");
  }
  return { ok: true, value: result };
}

function parseSurfaceDefaults(
  value: unknown,
  models: Readonly<Record<string, ModelManifestModelV2>>,
  tiers: ModelManifestTierBundlesV2,
): ParseResult<ModelManifestSurfaceDefaultsV2> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, MODEL_MANIFEST_TIERS);
  if (keyFailure !== null) return fail(keyFailure);
  const result = Object.create(null) as ModelManifestSurfaceDefaultsV2;
  for (const tier of MODEL_MANIFEST_TIERS) {
    const raw = value[tier];
    if (!isRecord(raw)) return fail("invalid_type");
    const surfaceFailure = checkExactKeys(raw, SURFACES);
    if (surfaceFailure !== null) return fail(surfaceFailure);
    const tierModels = new Set(tiers[tier]);
    const defaults = Object.create(null) as Record<Surface, string | null>;
    for (const surface of SURFACES) {
      const modelId = raw[surface];
      if (modelId === null) {
        defaults[surface] = null;
      } else if (
        typeof modelId === "string" && models[modelId] !== undefined &&
        tierModels.has(modelId)
      ) {
        defaults[surface] = modelId;
      } else {
        return fail("invalid_reference");
      }
    }
    result[tier] = defaults;
  }
  return { ok: true, value: result };
}

function parseBody(value: unknown): ParseResult<ModelManifestBodyV2> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, BODY_KEYS);
  if (keyFailure !== null) return fail(keyFailure);
  if (typeof value.schema_version !== "number") return fail("invalid_type");
  if (value.schema_version < MODEL_MANIFEST_V2_SCHEMA_VERSION) return fail("downgrade");
  if (value.schema_version > MODEL_MANIFEST_V2_SCHEMA_VERSION) return fail("invalid_value");
  if (
    typeof value.manifest_version !== "number" ||
    !Number.isInteger(value.manifest_version) || value.manifest_version < 1 ||
    value.manifest_version > MODEL_MANIFEST_MAX_VERSION
  ) {
    return fail("invalid_value");
  }
  const models = parseModels(value.models);
  if (!models.ok) return models;
  const tiers = parseTiers(value.tiers, models.value);
  if (!tiers.ok) return tiers;
  const defaults = parseSurfaceDefaults(value.surface_defaults, models.value, tiers.value);
  if (!defaults.ok) return defaults;
  return {
    ok: true,
    value: {
      schema_version: MODEL_MANIFEST_V2_SCHEMA_VERSION,
      manifest_version: value.manifest_version,
      models: models.value,
      tiers: tiers.value,
      surface_defaults: defaults.value,
    },
  };
}

function parseEnvelopeValue(value: unknown): ParseResult<SignedModelManifestV2> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, ENVELOPE_KEYS);
  if (keyFailure !== null) return fail(keyFailure);
  if (typeof value.signature !== "string") return fail("invalid_type");
  if (value.signature.length === 0) return fail("absent");
  // 86 = unpadded base64url length of ED25519_SIGNATURE_BYTES (64 bytes).
  if (value.signature.length > 86) return fail("bad_signature_encoding");
  const body = parseBody(value.body);
  if (!body.ok) return body;
  return { ok: true, value: { body: body.value, signature: value.signature } };
}

export function parseModelManifestV2Json(
  text: string | null | undefined,
): ParseResult<SignedModelManifestV2> {
  if (text === null || text === undefined || text.length === 0) return fail("absent");
  if (text.length > MODEL_MANIFEST_MAX_JSON_CHARS) return fail("manifest_too_large");
  let value: unknown;
  try {
    value = parseStrictJson(text);
  } catch (error) {
    if (error instanceof SubstrateError) {
      if (error.reason === "json_duplicate_key") return fail("duplicate_key");
      if (error.reason === "json_prototype_key") return fail("prototype_key");
    }
    return fail("malformed_json");
  }
  return parseEnvelopeValue(value);
}

export function buildModelManifestV2Message(body: ModelManifestBodyV2): Uint8Array {
  return stringToBytes(
    MODEL_MANIFEST_V2_DOMAIN + MODEL_MANIFEST_V2_DELIMITER + canonicalJson(body),
  );
}

export function computeModelManifestV2BodyDigest(body: ModelManifestBodyV2): string {
  return createHash("sha256").update(stringToBytes(canonicalJson(body))).digest("hex");
}

function isAllZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

function verifyParsedEnvelope(
  manifest: SignedModelManifestV2,
  publicKey: Uint8Array,
  floor?: number,
): ModelManifestV2VerificationResult {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    return { ok: false, reason: "bad_pinned_key_length" };
  }
  if (isAllZero(publicKey)) return { ok: false, reason: "zero_pinned_key" };
  if (
    floor !== undefined &&
    (!Number.isInteger(floor) || floor < 1 || floor > MODEL_MANIFEST_MAX_VERSION)
  ) {
    return { ok: false, reason: "invalid_version_floor" };
  }
  let signature: Uint8Array;
  try {
    signature = fromBase64urlStrict(manifest.signature);
  } catch {
    return { ok: false, reason: "bad_signature_encoding" };
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    return { ok: false, reason: "bad_signature_length" };
  }
  if (isAllZero(signature)) return { ok: false, reason: "zero_signature" };
  if (!verify(buildModelManifestV2Message(manifest.body), signature, publicKey)) {
    return { ok: false, reason: "bad_signature" };
  }
  if (floor !== undefined && manifest.body.manifest_version < floor) {
    return { ok: false, reason: "rollback" };
  }
  return { ok: true, manifest, body: manifest.body };
}

export function verifyModelManifestV2WithKey(
  text: string | null | undefined,
  publicKey: Uint8Array,
  options: { manifestVersionFloor?: number } = {},
): ModelManifestV2VerificationResult {
  const parsed = parseModelManifestV2Json(text);
  if (!parsed.ok) return parsed;
  return verifyParsedEnvelope(parsed.value, publicKey, options.manifestVersionFloor);
}

export function deriveOllamaRuntimeTag(identity: SignedOllamaIdentityV2): string {
  return identity.namespace === "library"
    ? `${identity.model}:${identity.tag}`
    : `${identity.namespace}/${identity.model}:${identity.tag}`;
}

export function deriveOllamaManifestRelativePath(
  identity: SignedOllamaIdentityV2,
): string {
  return posix.join(
    "manifests",
    identity.registry,
    identity.namespace,
    identity.model,
    identity.tag,
  );
}

function constantTimeHexEqual(left: string, right: string): boolean {
  if (!SHA256_HEX.test(left) || !SHA256_HEX.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function sameIdentity(
  left: SignedOllamaIdentityV2,
  right: SignedOllamaIdentityV2,
): boolean {
  return left.registry === right.registry && left.namespace === right.namespace &&
    left.model === right.model && left.tag === right.tag &&
    constantTimeHexEqual(left.ollama_manifest_sha256, right.ollama_manifest_sha256);
}

function parseBinding(
  surface: Surface,
  value: unknown,
  body: ModelManifestBodyV2,
): ParseResult<VerifiedLocalBindingV2> {
  if (!isRecord(value)) return fail("integrity_state_invalid");
  if (checkExactKeys(value, BINDING_KEYS) !== null) return fail("integrity_state_invalid");
  const modelId = boundedString(value.model_id);
  const runtimeTag = boundedString(value.runtime_tag);
  const identity = parseOllamaIdentity(value.ollama_identity);
  const expectedModel = modelId === null ? undefined : body.models[modelId];
  const modelIsDerivedForSurface = modelId !== null &&
    MODEL_MANIFEST_TIERS.some((tier) =>
      body.tiers[tier].includes(modelId) &&
      body.surface_defaults[tier][surface] === modelId
    );
  const expectedAssurance: ModelLoadIntegrityAssurance = IMMUNE_SURFACE_SET.has(surface)
    ? "immune"
    : "light";
  if (
    modelId === null || runtimeTag === null || !identity.ok || expectedModel === undefined ||
    // A signed model existing somewhere in the catalog is not authority for
    // another surface; rederive the surface/model edge on every state load.
    !modelIsDerivedForSurface ||
    value.assurance !== expectedAssurance ||
    value.manifest_version !== body.manifest_version ||
    runtimeTag !== deriveOllamaRuntimeTag(expectedModel.ollama_identity) ||
    !sameIdentity(identity.value, expectedModel.ollama_identity)
  ) {
    return fail("binding_mismatch");
  }
  return {
    ok: true,
    value: {
      model_id: modelId,
      runtime_tag: runtimeTag,
      ollama_identity: identity.value,
      assurance: expectedAssurance,
      manifest_version: body.manifest_version,
    },
  };
}

export function validateLocalIntegrityStateV2(
  value: unknown,
  publicKey: Uint8Array,
): LocalIntegrityStateV2ValidationResult {
  if (!isRecord(value) || checkExactKeys(value, STATE_KEYS) !== null) {
    return { ok: false, reason: "integrity_state_invalid" };
  }
  if (
    value.state !== "armed" || value.schema_version !== MODEL_MANIFEST_V2_SCHEMA_VERSION ||
    typeof value.manifest_version_floor !== "number" ||
    !Number.isInteger(value.manifest_version_floor) || value.manifest_version_floor < 1 ||
    value.manifest_version_floor > MODEL_MANIFEST_MAX_VERSION ||
    typeof value.signed_body_sha256 !== "string" ||
    typeof value.ollama_models_root !== "string" ||
    typeof value.committed_at !== "string" || !isRecord(value.bindings)
  ) {
    return { ok: false, reason: "integrity_state_invalid" };
  }
  if (!isAbsolute(value.ollama_models_root) || value.ollama_models_root.includes("\0")) {
    return { ok: false, reason: "model_root_invalid" };
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value.committed_at) ||
      parseIsoInstantWithOffset(value.committed_at) === undefined ||
      new Date(value.committed_at).toISOString() !== value.committed_at) {
    return { ok: false, reason: "integrity_state_invalid" };
  }
  const manifest = parseEnvelopeValue(value.signed_manifest);
  if (!manifest.ok) return { ok: false, reason: manifest.reason };
  const verified = verifyParsedEnvelope(
    manifest.value,
    publicKey,
    value.manifest_version_floor,
  );
  if (!verified.ok) return verified;
  // Armed state pins the floor to the exact committed version. Accepting a
  // merely newer floor would let a stale embedded manifest hide behind it.
  if (verified.body.manifest_version !== value.manifest_version_floor) {
    return { ok: false, reason: "integrity_state_invalid" };
  }
  const expectedBodyDigest = computeModelManifestV2BodyDigest(verified.body);
  if (!constantTimeHexEqual(value.signed_body_sha256, expectedBodyDigest)) {
    return { ok: false, reason: "integrity_state_invalid" };
  }
  const bindings = Object.create(null) as Partial<Record<Surface, VerifiedLocalBindingV2>>;
  let bindingCount = 0;
  for (const key in value.bindings) {
    if (!Object.prototype.hasOwnProperty.call(value.bindings, key)) continue;
    if (!SURFACES.includes(key as Surface)) {
      return { ok: false, reason: "integrity_state_invalid" };
    }
    const surface = key as Surface;
    const binding = parseBinding(surface, value.bindings[surface], verified.body);
    if (!binding.ok) return binding;
    bindings[surface] = binding.value;
    bindingCount += 1;
  }
  if (bindingCount === 0) return { ok: false, reason: "integrity_state_invalid" };
  return {
    ok: true,
    state: {
      state: "armed",
      schema_version: MODEL_MANIFEST_V2_SCHEMA_VERSION,
      manifest_version_floor: value.manifest_version_floor,
      signed_manifest: verified.manifest,
      signed_body_sha256: expectedBodyDigest,
      ollama_models_root: value.ollama_models_root,
      bindings,
      committed_at: value.committed_at,
    },
  };
}
