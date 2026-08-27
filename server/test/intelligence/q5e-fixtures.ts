import { ed25519 } from "@noble/curves/ed25519";
import { createHash } from "node:crypto";
import { toBase64url } from "../../src/core/encoding.js";
import {
  IMMUNE_MODEL_LOAD_SURFACES,
  computeModelManifestV2BodyDigest,
  type LocalIntegrityStateV2,
  type ModelManifestBodyV2,
  type ModelManifestModelV2,
  type SignedModelManifestV2,
  type VerifiedLocalBindingV2,
} from "../../src/intelligence/model-manifest-v2.js";
import { SURFACES, type Surface } from "../../src/intelligence/types.js";
import { canonicalJson } from "../../src/v1/operator-signed.js";

export const Q5E_PRIVATE_KEY = new Uint8Array(32).fill(41);
export const Q5E_PUBLIC_KEY = ed25519.getPublicKey(Q5E_PRIVATE_KEY);
export const Q5E_RUNTIME_TAG = "qwen2.5:1.5b";
export const Q5E_DEFAULT_DIGEST = "1".repeat(64);

export function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function q5eModel(
  manifestDigest = Q5E_DEFAULT_DIGEST,
): ModelManifestModelV2 {
  return {
    model_id: "qwen2.5-1.5b",
    model_name: "Qwen2.5 1.5B",
    model_version: "2.5",
    provider: "Alibaba Cloud",
    runtime: "ollama",
    ollama_identity: {
      registry: "registry.ollama.ai",
      namespace: "library",
      model: "qwen2.5",
      tag: "1.5b",
      ollama_manifest_sha256: manifestDigest,
    },
    params_b: 1.5,
    license: {
      identifier: "Apache-2.0",
      name: "Apache License 2.0",
      url: "https://www.apache.org/licenses/LICENSE-2.0",
      osi_approved: true,
      redistribution: "permitted",
    },
    open_weights: true,
    open_source: false,
  };
}

export function q5eBody(
  manifestDigest = Q5E_DEFAULT_DIGEST,
  manifestVersion = 17,
): ModelManifestBodyV2 {
  const model = q5eModel(manifestDigest);
  const defaults = Object.fromEntries(SURFACES.map((surface) => [
    surface,
    surface === "gate-explanation" ? null : model.model_id,
  ])) as Record<Surface, string | null>;
  return {
    schema_version: 2,
    manifest_version: manifestVersion,
    models: { [model.model_id]: model },
    tiers: {
      baseline: [model.model_id],
      mid: [model.model_id],
      pro: [model.model_id],
    },
    surface_defaults: {
      baseline: structuredClone(defaults),
      mid: structuredClone(defaults),
      pro: structuredClone(defaults),
    },
  };
}

export function signQ5eBody(body: ModelManifestBodyV2): SignedModelManifestV2 {
  const message = new TextEncoder().encode(
    `sanctuary.model-manifest.v2\n${canonicalJson(body)}`,
  );
  return {
    body,
    signature: toBase64url(ed25519.sign(message, Q5E_PRIVATE_KEY)),
  };
}

export function q5eBinding(
  surface: Surface,
  body: ModelManifestBodyV2,
): VerifiedLocalBindingV2 {
  const model = body.models["qwen2.5-1.5b"]!;
  return {
    model_id: model.model_id,
    runtime_tag: Q5E_RUNTIME_TAG,
    ollama_identity: structuredClone(model.ollama_identity),
    assurance: IMMUNE_MODEL_LOAD_SURFACES.includes(
      surface as (typeof IMMUNE_MODEL_LOAD_SURFACES)[number],
    ) ? "immune" : "light",
    manifest_version: body.manifest_version,
  };
}

export function q5eIntegrityState(
  rootReal: string,
  body = q5eBody(),
): LocalIntegrityStateV2 {
  const bindings = Object.create(null) as Partial<Record<Surface, VerifiedLocalBindingV2>>;
  for (const surface of SURFACES) {
    if (surface !== "gate-explanation") bindings[surface] = q5eBinding(surface, body);
  }
  return {
    state: "armed",
    schema_version: 2,
    manifest_version_floor: body.manifest_version,
    signed_manifest: signQ5eBody(body),
    signed_body_sha256: computeModelManifestV2BodyDigest(body),
    ollama_models_root: rootReal,
    bindings,
    committed_at: "2026-08-26T12:00:00.000Z",
  };
}

export function q5eRuntimeTags(state: LocalIntegrityStateV2) {
  return Object.fromEntries(
    Object.entries(state.bindings).map(([surface, binding]) => [
      surface,
      binding!.runtime_tag,
    ]),
  ) as Partial<Record<Surface, string>>;
}
