/**
 * Sanctuary MCP Server - signed local-model manifest contract.
 *
 * A registry tag is mutable metadata, not proof of which weights will run.
 * This module authenticates a bounded, exact-schema assertion made by the
 * Sanctuary release signer. It performs no fetch, pull, install, selection,
 * or substrate mutation. Callers may use only the typed body returned by the
 * verifier; the manifest never has authority to change a configured substrate.
 */

import { canonicalJson } from "../v1/operator-signed.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../core/crypto-suite-registry.js";
import { fromBase64urlStrict, stringToBytes } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import {
  loadPinnedReleaseKey,
  PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL,
} from "../release-manifest.js";
import type { ModelProvenance } from "../operational/model-provenance.js";
import { SubstrateError } from "../substrate/errors.js";
import { parseStrictJson } from "../substrate/strict-json.js";
import { SURFACES, type Surface } from "./types.js";

/** Frozen signing domain. A future schema uses a new domain, never this one. */
export const MODEL_MANIFEST_DOMAIN = "sanctuary.model-manifest.v1";

/**
 * Frozen framing delimiter. This must match the verifier and any release-side
 * signer: the delimiter prevents prefix ambiguity between the domain and body.
 */
export const MODEL_MANIFEST_DELIMITER = "\n";

/** The model contract reuses the current release-signing public key. */
export const PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL =
  PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL;

export const MODEL_MANIFEST_TIERS = ["baseline", "mid", "pro"] as const;
export type ModelManifestTier = (typeof MODEL_MANIFEST_TIERS)[number];

export const MODEL_MANIFEST_RUNTIMES = ["ollama"] as const;
export type ModelManifestRuntime = (typeof MODEL_MANIFEST_RUNTIMES)[number];

export const MODEL_LICENSE_REDISTRIBUTION = [
  "permitted",
  "conditional",
  "restricted",
  "unknown",
] as const;
export type ModelLicenseRedistribution =
  (typeof MODEL_LICENSE_REDISTRIBUTION)[number];

// Caps apply before regex, URL parsing, canonicalization, or collection walks.
export const MODEL_MANIFEST_MAX_JSON_CHARS = 256 * 1024;
export const MODEL_MANIFEST_MAX_MODELS = 32;
export const MODEL_MANIFEST_MAX_MODELS_PER_TIER = 32;
export const MODEL_MANIFEST_MAX_STRING_CHARS = 256;
export const MODEL_MANIFEST_MAX_URL_CHARS = 2_048;
export const MODEL_MANIFEST_MIN_PARAMS_B = 0.01;
export const MODEL_MANIFEST_MAX_PARAMS_B = 1_000;
export const MODEL_MANIFEST_MAX_VERSION = 2_147_483_647;

/**
 * License assertion made by the release signer for one exact model entry.
 * Subject: `ModelManifestModel.model_id`. Evidence: the upstream license URL.
 * Verifier: this exact-schema parser plus the manifest Ed25519 signature.
 * Meaning: provenance may repeat the identifier, but may not infer broader
 * rights or OSI status beyond the signed fields.
 */
export interface ModelLicenseMetadata {
  identifier: string;
  name: string;
  url: string;
  osi_approved: boolean;
  redistribution: ModelLicenseRedistribution;
}

/** One release-signer assertion about an exact local model artifact. */
export interface ModelManifestModel {
  /** Semantic subject; must equal the containing `models` key. */
  model_id: string;
  model_name: string;
  model_version: string;
  provider: string;
  runtime: ModelManifestRuntime;
  /** Runtime lookup subject; data only and never executed by this module. */
  runtime_tag: string;
  /** Evidence location; must be the safe `ollama://<runtime_tag>` form. */
  registry_source: string;
  /** Verifier input: lowercase SHA-256 of the upstream model artifact. */
  weights_sha256: string;
  params_b: number;
  license: ModelLicenseMetadata;
  /** Public weight availability; this does not mean OSI open-source. */
  open_weights: boolean;
  /** Full-source assertion, permitted only with open weights + OSI license. */
  open_source: boolean;
}

export type ModelManifestTierBundles = Record<
  ModelManifestTier,
  readonly string[]
>;

/**
 * Per-tier model choices for every wired intelligence surface. Values are
 * model identities or null when that tier deliberately has no model default.
 * These values select a model only after a caller has independently decided
 * to use the local substrate; they never select or relax the substrate itself.
 */
export type ModelManifestSurfaceDefaults = Record<
  ModelManifestTier,
  Record<Surface, string | null>
>;

export interface ModelManifestBody {
  /** Monotonic release-signer sequence, independent of npm package version. */
  manifest_version: number;
  models: Record<string, ModelManifestModel>;
  tiers: ModelManifestTierBundles;
  surface_defaults: ModelManifestSurfaceDefaults;
}

export interface SignedModelManifest {
  body: ModelManifestBody;
  signature: string;
}

/** Closed, machine-stable refusal taxonomy for the trust boundary. */
export type ModelManifestRefusalReason =
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
  | "unsafe_registry_source"
  | "license_contradiction"
  | "bad_signature_encoding"
  | "bad_signature_length"
  | "zero_signature"
  | "bad_signature"
  | "bad_pinned_key_length"
  | "zero_pinned_key"
  | "invalid_version_floor"
  | "rollback";

export type ModelManifestVerificationResult =
  | { ok: true; body: ModelManifestBody }
  | { ok: false; reason: ModelManifestRefusalReason };

export interface ModelManifestVerificationOptions {
  /** Last successfully verified version; lower versions refuse as rollback. */
  lastVerifiedManifestVersion?: number;
}

type ParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: ModelManifestRefusalReason };

const BODY_KEYS = [
  "manifest_version",
  "models",
  "tiers",
  "surface_defaults",
] as const;
const ENVELOPE_KEYS = ["body", "signature"] as const;
const MODEL_KEYS = [
  "model_id",
  "model_name",
  "model_version",
  "provider",
  "runtime",
  "runtime_tag",
  "registry_source",
  "weights_sha256",
  "params_b",
  "license",
  "open_weights",
  "open_source",
] as const;
const LICENSE_KEYS = [
  "identifier",
  "name",
  "url",
  "osi_approved",
  "redistribution",
] as const;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const ALL_ZERO_SHA256 = "0".repeat(64);
const MODEL_ID = /^[a-z0-9][a-z0-9._-]*$/;
const OLLAMA_TAG =
  /^(?:[a-z0-9][a-z0-9._-]{0,63}\/){0,4}[a-z0-9][a-z0-9._-]{0,63}(?::[a-z0-9][a-z0-9._-]{0,63})?$/;

function fail<T>(reason: ModelManifestRefusalReason): ParseResult<T> {
  return { ok: false, reason };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Exact-key check without allocating an attacker-sized keys array. */
function checkExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): ModelManifestRefusalReason | null {
  let count = 0;
  const seen = new Set<string>();
  for (const key in value) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    count += 1;
    if (count > expected.length) return "unknown_key";
    if (!expected.includes(key)) return "unknown_key";
    seen.add(key);
  }
  for (const key of expected) {
    if (!seen.has(key)) return "missing_key";
  }
  return null;
}

function boundedString(
  value: unknown,
  maxChars = MODEL_MANIFEST_MAX_STRING_CHARS,
): string | null {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > maxChars) return null;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return null;
  }
  return value;
}

function parseHttpsUrl(value: unknown): string | null {
  const text = boundedString(value, MODEL_MANIFEST_MAX_URL_CHARS);
  if (text === null) return null;
  try {
    const url = new URL(text);
    if (url.protocol !== "https:" || url.username !== "" || url.password !== "") {
      return null;
    }
    return text;
  } catch {
    return null;
  }
}

function parseLicense(value: unknown): ParseResult<ModelLicenseMetadata> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, LICENSE_KEYS);
  if (keyFailure !== null) return fail(keyFailure);

  const identifier = boundedString(value.identifier);
  const name = boundedString(value.name);
  const url = parseHttpsUrl(value.url);
  if (identifier === null || name === null || url === null) {
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
    (identifier.toLowerCase() === "unknown" ||
      identifier.toLowerCase() === "proprietary")
  ) {
    return fail("license_contradiction");
  }
  return {
    ok: true,
    value: {
      identifier,
      name,
      url,
      osi_approved: value.osi_approved,
      redistribution: value.redistribution as ModelLicenseRedistribution,
    },
  };
}

function parseModel(
  modelId: string,
  value: unknown,
): ParseResult<ModelManifestModel> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, MODEL_KEYS);
  if (keyFailure !== null) return fail(keyFailure);

  const declaredId = boundedString(value.model_id);
  const modelName = boundedString(value.model_name);
  const modelVersion = boundedString(value.model_version);
  const provider = boundedString(value.provider);
  const runtimeTag = boundedString(value.runtime_tag);
  const registrySource = boundedString(value.registry_source);
  const weightsSha256 = boundedString(value.weights_sha256);
  if (
    declaredId === null ||
    declaredId !== modelId ||
    !MODEL_ID.test(declaredId) ||
    modelName === null ||
    modelVersion === null ||
    provider === null ||
    runtimeTag === null ||
    registrySource === null ||
    weightsSha256 === null
  ) {
    return fail("invalid_value");
  }
  if (value.runtime !== "ollama" || !OLLAMA_TAG.test(runtimeTag)) {
    return fail("invalid_value");
  }
  if (registrySource !== `ollama://${runtimeTag}`) {
    return fail("unsafe_registry_source");
  }
  if (!SHA256_HEX.test(weightsSha256) || weightsSha256 === ALL_ZERO_SHA256) {
    return fail("invalid_value");
  }
  if (
    typeof value.params_b !== "number" ||
    !Number.isFinite(value.params_b) ||
    value.params_b < MODEL_MANIFEST_MIN_PARAMS_B ||
    value.params_b > MODEL_MANIFEST_MAX_PARAMS_B
  ) {
    return fail("invalid_value");
  }
  if (
    typeof value.open_weights !== "boolean" ||
    typeof value.open_source !== "boolean"
  ) {
    return fail("invalid_type");
  }

  const license = parseLicense(value.license);
  if (!license.ok) return license;
  if (
    value.open_source &&
    (!value.open_weights || !license.value.osi_approved)
  ) {
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
      runtime_tag: runtimeTag,
      registry_source: registrySource,
      weights_sha256: weightsSha256,
      params_b: value.params_b,
      license: license.value,
      open_weights: value.open_weights,
      open_source: value.open_source,
    },
  };
}

function parseModels(
  value: unknown,
): ParseResult<Record<string, ModelManifestModel>> {
  if (!isRecord(value)) return fail("invalid_type");
  const models: Record<string, ModelManifestModel> = Object.create(null) as Record<
    string,
    ModelManifestModel
  >;
  let count = 0;
  for (const modelId in value) {
    if (!Object.prototype.hasOwnProperty.call(value, modelId)) continue;
    count += 1;
    if (count > MODEL_MANIFEST_MAX_MODELS) return fail("collection_too_large");
    if (
      modelId.length === 0 ||
      modelId.length > MODEL_MANIFEST_MAX_STRING_CHARS ||
      !MODEL_ID.test(modelId)
    ) {
      return fail("invalid_value");
    }
    const model = parseModel(modelId, value[modelId]);
    if (!model.ok) return model;
    models[modelId] = model.value;
  }
  return count === 0 ? fail("invalid_value") : { ok: true, value: models };
}

function parseTiers(
  value: unknown,
  models: Readonly<Record<string, ModelManifestModel>>,
): ParseResult<ModelManifestTierBundles> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, MODEL_MANIFEST_TIERS);
  if (keyFailure !== null) return fail(keyFailure);
  const tiers = Object.create(null) as Record<ModelManifestTier, string[]>;
  const assigned = new Set<string>();
  for (const tier of MODEL_MANIFEST_TIERS) {
    const raw = value[tier];
    if (!Array.isArray(raw)) return fail("invalid_type");
    if (raw.length === 0) return fail("invalid_value");
    if (raw.length > MODEL_MANIFEST_MAX_MODELS_PER_TIER) {
      return fail("collection_too_large");
    }
    const ids: string[] = [];
    const seen = new Set<string>();
    for (const item of raw) {
      if (typeof item !== "string" || models[item] === undefined) {
        return fail("invalid_reference");
      }
      if (seen.has(item)) return fail("invalid_reference");
      seen.add(item);
      assigned.add(item);
      ids.push(item);
    }
    tiers[tier] = ids;
  }
  for (const modelId in models) {
    if (!assigned.has(modelId)) return fail("invalid_reference");
  }
  return { ok: true, value: tiers };
}

function parseSurfaceDefaults(
  value: unknown,
  models: Readonly<Record<string, ModelManifestModel>>,
  tiers: ModelManifestTierBundles,
): ParseResult<ModelManifestSurfaceDefaults> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, MODEL_MANIFEST_TIERS);
  if (keyFailure !== null) return fail(keyFailure);
  const defaults = Object.create(null) as ModelManifestSurfaceDefaults;
  for (const tier of MODEL_MANIFEST_TIERS) {
    const raw = value[tier];
    if (!isRecord(raw)) return fail("invalid_type");
    const surfaceKeyFailure = checkExactKeys(raw, SURFACES);
    if (surfaceKeyFailure !== null) return fail(surfaceKeyFailure);
    const tierDefaults = Object.create(null) as Record<Surface, string | null>;
    const tierMembers = new Set(tiers[tier]);
    for (const surface of SURFACES) {
      const modelId = raw[surface];
      if (modelId === null) {
        tierDefaults[surface] = null;
        continue;
      }
      if (
        typeof modelId !== "string" ||
        models[modelId] === undefined ||
        !tierMembers.has(modelId)
      ) {
        return fail("invalid_reference");
      }
      tierDefaults[surface] = modelId;
    }
    defaults[tier] = tierDefaults;
  }
  return { ok: true, value: defaults };
}

function parseBody(value: unknown): ParseResult<ModelManifestBody> {
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, BODY_KEYS);
  if (keyFailure !== null) return fail(keyFailure);
  if (
    typeof value.manifest_version !== "number" ||
    !Number.isInteger(value.manifest_version) ||
    value.manifest_version < 1 ||
    value.manifest_version > MODEL_MANIFEST_MAX_VERSION
  ) {
    return fail("invalid_value");
  }
  const models = parseModels(value.models);
  if (!models.ok) return models;
  const tiers = parseTiers(value.tiers, models.value);
  if (!tiers.ok) return tiers;
  const surfaceDefaults = parseSurfaceDefaults(
    value.surface_defaults,
    models.value,
    tiers.value,
  );
  if (!surfaceDefaults.ok) return surfaceDefaults;
  return {
    ok: true,
    value: {
      manifest_version: value.manifest_version,
      models: models.value,
      tiers: tiers.value,
      surface_defaults: surfaceDefaults.value,
    },
  };
}

/**
 * Shared runtime parser. Duplicate semantic keys are detectable only in JSON
 * text, so the trust boundary accepts text rather than an already-collapsed
 * `JSON.parse` object. Every verifier and future fetch consumer uses this.
 */
export function parseModelManifestJson(
  text: string | null | undefined,
): ParseResult<SignedModelManifest> {
  if (text === null || text === undefined || text.length === 0) {
    return fail("absent");
  }
  if (text.length > MODEL_MANIFEST_MAX_JSON_CHARS) {
    return fail("manifest_too_large");
  }
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
  if (!isRecord(value)) return fail("invalid_type");
  const keyFailure = checkExactKeys(value, ENVELOPE_KEYS);
  if (keyFailure !== null) return fail(keyFailure);
  if (typeof value.signature !== "string") return fail("invalid_type");
  // Ed25519 signatures encode to exactly 86 unpadded base64url characters.
  if (value.signature.length === 0) return fail("absent");
  if (value.signature.length > 86) return fail("bad_signature_encoding");
  const body = parseBody(value.body);
  if (!body.ok) return body;
  return { ok: true, value: { body: body.value, signature: value.signature } };
}

/** Exact signed bytes: domain, one newline delimiter, canonical body JSON. */
export function buildModelManifestMessage(body: ModelManifestBody): Uint8Array {
  return stringToBytes(
    MODEL_MANIFEST_DOMAIN + MODEL_MANIFEST_DELIMITER + canonicalJson(body),
  );
}

function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i += 1) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

export function verifyModelManifestWithKey(
  text: string | null | undefined,
  publicKey: Uint8Array,
  options: ModelManifestVerificationOptions = {},
): ModelManifestVerificationResult {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    return { ok: false, reason: "bad_pinned_key_length" };
  }
  if (isAllZero(publicKey)) return { ok: false, reason: "zero_pinned_key" };

  const floor = options.lastVerifiedManifestVersion;
  if (
    floor !== undefined &&
    (!Number.isInteger(floor) || floor < 0 || floor > MODEL_MANIFEST_MAX_VERSION)
  ) {
    return { ok: false, reason: "invalid_version_floor" };
  }

  const parsed = parseModelManifestJson(text);
  if (!parsed.ok) return parsed;

  let signature: Uint8Array;
  try {
    signature = fromBase64urlStrict(parsed.value.signature);
  } catch {
    return { ok: false, reason: "bad_signature_encoding" };
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    return { ok: false, reason: "bad_signature_length" };
  }
  if (isAllZero(signature)) return { ok: false, reason: "zero_signature" };

  let message: Uint8Array;
  try {
    message = buildModelManifestMessage(parsed.value.body);
  } catch {
    return { ok: false, reason: "invalid_value" };
  }
  if (!verify(message, signature, publicKey)) {
    return { ok: false, reason: "bad_signature" };
  }

  if (
    floor !== undefined &&
    parsed.value.body.manifest_version < floor
  ) {
    return { ok: false, reason: "rollback" };
  }
  return { ok: true, body: parsed.value.body };
}

export function loadPinnedModelManifestKey(): Uint8Array | null {
  return loadPinnedReleaseKey();
}

export function verifyModelManifest(
  text: string | null | undefined,
  options: ModelManifestVerificationOptions = {},
): ModelManifestVerificationResult {
  const key = loadPinnedModelManifestKey();
  if (key === null) return { ok: false, reason: "bad_pinned_key_length" };
  return verifyModelManifestWithKey(text, key, options);
}

export function resolveModelForSurface(
  body: ModelManifestBody,
  tier: ModelManifestTier,
  surface: Surface,
): ModelManifestModel | null {
  const modelId = body.surface_defaults[tier][surface];
  return modelId === null ? null : body.models[modelId] ?? null;
}

/**
 * Convert the historical V1 release-signer assertion into provenance. V1's
 * digest was sourced from Ollama's model-manifest identity, not a weights file;
 * Q5A therefore records it under the corrected evidence name. This does not arm
 * Q5 or claim that constituent layer bytes were hashed.
 */
export function provenanceFromVerifiedModelManifest(
  model: ModelManifestModel,
  declaredAt = new Date().toISOString(),
): ModelProvenance {
  return {
    model_id: model.model_id,
    model_name: model.model_name,
    model_version: model.model_version,
    provider: model.provider,
    runtime_manifest_hash: `sha256:${model.weights_sha256}`,
    license: model.license.identifier,
    open_weights: model.open_weights,
    open_source: model.open_source,
    local_inference: true,
    declared_at: declaredAt,
  };
}
