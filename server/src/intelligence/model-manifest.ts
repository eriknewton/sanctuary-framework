/**
 * Sanctuary MCP Server - Signed local model manifest verification.
 *
 * Local intelligence provisioning must not trust an Ollama tag by name alone:
 * tags can be repointed and on-disk weights can be substituted. This verifier
 * authenticates the model bundle metadata that P1 provisioning will pull
 * against. The network may deliver bytes, but the pinned Ed25519 key decides
 * whether those bytes are a Sanctuary model manifest.
 *
 * The release verifier already established the signing key and the strict
 * base64url / all-zero guard discipline. This module intentionally uses a
 * distinct domain separator so a signed release manifest cannot be replayed as
 * a signed model manifest.
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
import { SURFACES, type Surface } from "./types.js";

/** Domain separator for the model-manifest signature (versioned). */
export const MODEL_MANIFEST_DOMAIN = "sanctuary.model-manifest.v1";

/** Model manifests reuse the live release-signing public key under a new domain. */
export const PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL =
  PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL;

export type ModelManifestTier = "baseline" | "mid" | "pro";

export const MODEL_MANIFEST_TIERS: readonly ModelManifestTier[] = [
  "baseline",
  "mid",
  "pro",
] as const;

export type ModelRuntime = "ollama";

export interface ModelManifestModel {
  /** Must match the key under `body.models`. */
  model_id: string;
  model_name: string;
  model_version: string;
  provider: string;
  runtime: ModelRuntime;
  /** Runtime-local identifier, for Ollama this is the tag passed to `/api/pull`. */
  runtime_tag: string;
  /** Registry pointer, for example `ollama://qwen2.5:1.5b`. */
  registry_source: string;
  /** Lowercase hex SHA-256 digest of the resolved model weights/blob set. */
  weights_sha256: string;
  /** Parameter count in billions, used for operator-facing plan sizing. */
  params_b: number;
  license: string;
  license_url: string;
  /** Weights are public enough to be pulled/inspected, even if not OSI open-source. */
  open_weights: boolean;
  /** Full training code/data/methodology are public under an OSI-style license. */
  open_source: boolean;
  /** The manifest is for Sanctuary's local intelligence runtime only. */
  local_inference: true;
}

export type ModelManifestTierBundle = Record<
  ModelManifestTier,
  readonly string[]
>;

export type ModelManifestSurfaceDefaults = Record<
  ModelManifestTier,
  Record<Surface, string | null>
>;

/**
 * The signed body of a local model manifest. These fields, and only these
 * fields, are covered by the detached Ed25519 signature.
 */
export interface ModelManifestBody {
  /** Monotonic integer; callers pass a floor to reject rollbacks. */
  manifest_version: number;
  models: Record<string, ModelManifestModel>;
  tiers: ModelManifestTierBundle;
  surface_defaults: ModelManifestSurfaceDefaults;
}

/** The on-the-wire signed model manifest: body plus detached signature. */
export interface SignedModelManifest {
  body: ModelManifestBody;
  /** base64url-encoded Ed25519 signature over the canonical signed message. */
  signature: string;
}

export type ModelManifestRefusalReason =
  | "malformed"
  | "bad_signature"
  | "bad_pinned_key"
  | "stale_version";

export type ModelManifestVerificationResult =
  | { ok: true; body: ModelManifestBody }
  | { ok: false; reason: ModelManifestRefusalReason };

export interface ModelManifestVerificationOptions {
  /**
   * Reject a correctly signed manifest whose monotonic version is below this
   * floor. This is the anti-rollback hook P1 persists after first success.
   */
  minimumManifestVersion?: number;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;
const ALL_ZERO_SHA256 =
  "0000000000000000000000000000000000000000000000000000000000000000";

function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactlyKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value);
  if (actual.length !== expected.length) return false;
  for (const key of actual) {
    if (!expected.includes(key)) return false;
  }
  return true;
}

function parseNonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function parseModel(
  modelId: string,
  value: unknown,
): ModelManifestModel | null {
  if (!isRecord(value)) return null;
  const expected = [
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
    "license_url",
    "open_weights",
    "open_source",
    "local_inference",
  ] as const;
  if (!hasExactlyKeys(value, expected)) return null;

  const declaredId = parseNonEmptyString(value.model_id);
  const modelName = parseNonEmptyString(value.model_name);
  const modelVersion = parseNonEmptyString(value.model_version);
  const provider = parseNonEmptyString(value.provider);
  const runtimeTag = parseNonEmptyString(value.runtime_tag);
  const registrySource = parseNonEmptyString(value.registry_source);
  const weightsSha256 = parseNonEmptyString(value.weights_sha256);
  const license = parseNonEmptyString(value.license);
  const licenseUrl = parseNonEmptyString(value.license_url);

  if (
    declaredId === null ||
    declaredId !== modelId ||
    modelName === null ||
    modelVersion === null ||
    provider === null ||
    value.runtime !== "ollama" ||
    runtimeTag === null ||
    registrySource === null ||
    weightsSha256 === null ||
    !SHA256_HEX.test(weightsSha256) ||
    weightsSha256 === ALL_ZERO_SHA256 ||
    typeof value.params_b !== "number" ||
    !Number.isFinite(value.params_b) ||
    value.params_b <= 0 ||
    license === null ||
    licenseUrl === null ||
    typeof value.open_weights !== "boolean" ||
    typeof value.open_source !== "boolean" ||
    value.local_inference !== true
  ) {
    return null;
  }

  return {
    model_id: declaredId,
    model_name: modelName,
    model_version: modelVersion,
    provider,
    runtime: "ollama",
    runtime_tag: runtimeTag,
    registry_source: registrySource,
    weights_sha256: weightsSha256,
    params_b: value.params_b,
    license,
    license_url: licenseUrl,
    open_weights: value.open_weights,
    open_source: value.open_source,
    local_inference: true,
  };
}

function parseModelMap(value: unknown): Record<string, ModelManifestModel> | null {
  if (!isRecord(value)) return null;
  const models: Record<string, ModelManifestModel> = {};
  const entries = Object.entries(value);
  if (entries.length === 0) return null;
  for (const [modelId, rawModel] of entries) {
    if (modelId.length === 0) return null;
    const model = parseModel(modelId, rawModel);
    if (model === null) return null;
    models[modelId] = model;
  }
  return models;
}

function parseTierBundle(
  value: unknown,
  knownModelIds: ReadonlySet<string>,
): ModelManifestTierBundle | null {
  if (!isRecord(value)) return null;
  if (!hasExactlyKeys(value, MODEL_MANIFEST_TIERS)) return null;

  const out = {} as Record<ModelManifestTier, string[]>;
  for (const tier of MODEL_MANIFEST_TIERS) {
    const raw = value[tier];
    if (!Array.isArray(raw)) return null;
    const seen = new Set<string>();
    const ids: string[] = [];
    for (const item of raw) {
      if (typeof item !== "string" || !knownModelIds.has(item) || seen.has(item)) {
        return null;
      }
      seen.add(item);
      ids.push(item);
    }
    out[tier] = ids;
  }
  return out;
}

function parseSurfaceDefaults(
  value: unknown,
  knownModelIds: ReadonlySet<string>,
): ModelManifestSurfaceDefaults | null {
  if (!isRecord(value)) return null;
  if (!hasExactlyKeys(value, MODEL_MANIFEST_TIERS)) return null;

  const out = {} as ModelManifestSurfaceDefaults;
  for (const tier of MODEL_MANIFEST_TIERS) {
    const rawTierDefaults = value[tier];
    if (!isRecord(rawTierDefaults)) return null;
    if (!hasExactlyKeys(rawTierDefaults, SURFACES)) return null;

    const tierDefaults = {} as Record<Surface, string | null>;
    for (const surface of SURFACES) {
      const modelId = rawTierDefaults[surface];
      if (modelId === null) {
        tierDefaults[surface] = null;
      } else if (typeof modelId === "string" && knownModelIds.has(modelId)) {
        tierDefaults[surface] = modelId;
      } else {
        return null;
      }
    }
    out[tier] = tierDefaults;
  }
  return out;
}

function parseManifestBody(value: unknown): ModelManifestBody | null {
  if (!isRecord(value)) return null;
  const expected = [
    "manifest_version",
    "models",
    "tiers",
    "surface_defaults",
  ] as const;
  if (!hasExactlyKeys(value, expected)) return null;

  if (
    typeof value.manifest_version !== "number" ||
    !Number.isInteger(value.manifest_version) ||
    value.manifest_version < 1
  ) {
    return null;
  }

  const models = parseModelMap(value.models);
  if (models === null) return null;
  const knownModelIds = new Set(Object.keys(models));

  const tiers = parseTierBundle(value.tiers, knownModelIds);
  if (tiers === null) return null;

  const surfaceDefaults = parseSurfaceDefaults(
    value.surface_defaults,
    knownModelIds,
  );
  if (surfaceDefaults === null) return null;

  return {
    manifest_version: value.manifest_version,
    models,
    tiers,
    surface_defaults: surfaceDefaults,
  };
}

function parseSignedModelManifest(value: unknown): SignedModelManifest | null {
  if (!isRecord(value)) return null;
  if (!hasExactlyKeys(value, ["body", "signature"])) return null;

  const signature = parseNonEmptyString(value.signature);
  if (signature === null) return null;

  const body = parseManifestBody(value.body);
  if (body === null) return null;

  return { body, signature };
}

/**
 * Build the exact byte string signed for a local model manifest:
 *   domain separator || canonical-JSON(body)
 */
export function buildModelManifestMessage(
  body: ModelManifestBody,
): Uint8Array {
  const domain = stringToBytes(MODEL_MANIFEST_DOMAIN);
  const payload = stringToBytes(canonicalJson(body));
  const message = new Uint8Array(domain.length + payload.length);
  message.set(domain, 0);
  message.set(payload, domain.length);
  return message;
}

export function verifyModelManifestWithKey(
  value: unknown,
  publicKey: Uint8Array,
  options: ModelManifestVerificationOptions = {},
): ModelManifestVerificationResult {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES || isAllZero(publicKey)) {
    return { ok: false, reason: "bad_pinned_key" };
  }

  const manifest = parseSignedModelManifest(value);
  if (manifest === null) {
    return { ok: false, reason: "malformed" };
  }

  let signature: Uint8Array;
  try {
    signature = fromBase64urlStrict(manifest.signature);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    return { ok: false, reason: "malformed" };
  }
  if (isAllZero(signature)) {
    return { ok: false, reason: "bad_signature" };
  }

  let message: Uint8Array;
  try {
    message = buildModelManifestMessage(manifest.body);
  } catch {
    return { ok: false, reason: "malformed" };
  }

  if (!verify(message, signature, publicKey)) {
    return { ok: false, reason: "bad_signature" };
  }

  const floor = options.minimumManifestVersion;
  if (
    typeof floor === "number" &&
    Number.isInteger(floor) &&
    manifest.body.manifest_version < floor
  ) {
    return { ok: false, reason: "stale_version" };
  }

  return { ok: true, body: manifest.body };
}

export function loadPinnedModelManifestKey(): Uint8Array | null {
  return loadPinnedReleaseKey();
}

export function verifyModelManifest(
  value: unknown,
  options: ModelManifestVerificationOptions = {},
): ModelManifestVerificationResult {
  const pinned = loadPinnedModelManifestKey();
  if (pinned === null) {
    return { ok: false, reason: "bad_pinned_key" };
  }
  return verifyModelManifestWithKey(value, pinned, options);
}

export function resolveModelForSurface(
  body: ModelManifestBody,
  tier: ModelManifestTier,
  surface: Surface,
): ModelManifestModel | null {
  const modelId = body.surface_defaults[tier][surface];
  return modelId === null ? null : body.models[modelId] ?? null;
}

export function provenanceFromModelManifestModel(
  model: ModelManifestModel,
  declaredAt: string = new Date().toISOString(),
): ModelProvenance {
  return {
    model_id: model.model_id,
    model_name: model.model_name,
    model_version: model.model_version,
    provider: model.provider,
    weights_hash: `sha256:${model.weights_sha256}`,
    license: model.license,
    open_weights: model.open_weights,
    open_source: model.open_source,
    local_inference: model.local_inference,
    declared_at: declaredAt,
  };
}
