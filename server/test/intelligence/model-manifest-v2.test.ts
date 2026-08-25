import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import { toBase64url } from "../../src/core/encoding.js";
import { canonicalJson } from "../../src/v1/operator-signed.js";
import * as intelligence from "../../src/intelligence/index.js";
import {
  IMMUNE_MODEL_LOAD_SURFACES,
  MODEL_MANIFEST_V2_DELIMITER,
  MODEL_MANIFEST_V2_DOMAIN,
  MODEL_MANIFEST_V2_REGISTRY,
  MODEL_MANIFEST_V2_SCHEMA_VERSION,
  buildModelManifestV2Message,
  computeModelManifestV2BodyDigest,
  deriveOllamaManifestRelativePath,
  deriveOllamaRuntimeTag,
  parseModelManifestV2Json,
  validateLocalIntegrityStateV2,
  verifyModelManifestV2WithKey,
  type LocalIntegrityStateV2,
  type ModelManifestBodyV2,
  type ModelManifestModelV2,
  type SignedModelManifestV2,
} from "../../src/intelligence/model-manifest-v2.js";
import { MODEL_MANIFEST_DOMAIN } from "../../src/intelligence/model-manifest.js";
import { SURFACES } from "../../src/intelligence/types.js";
import VECTOR from "../fixtures/model-manifest-v2-vector.json";

const PRIVATE_KEY = new Uint8Array(32).fill(19);
const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY);
const DIGEST = "1".repeat(64);

const MODEL: ModelManifestModelV2 = {
  model_id: "qwen2.5-1.5b",
  model_name: "Qwen2.5 1.5B Instruct",
  model_version: "2.5",
  provider: "Alibaba Cloud",
  runtime: "ollama",
  ollama_identity: {
    registry: MODEL_MANIFEST_V2_REGISTRY,
    namespace: "library",
    model: "qwen2.5",
    tag: "1.5b",
    ollama_manifest_sha256: DIGEST,
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

const DEFAULTS = Object.fromEntries(
  SURFACES.map((surface) => [surface, MODEL.model_id]),
) as Record<(typeof SURFACES)[number], string | null>;

const BODY: ModelManifestBodyV2 = {
  schema_version: 2,
  manifest_version: 9,
  models: { [MODEL.model_id]: MODEL },
  tiers: {
    baseline: [MODEL.model_id],
    mid: [MODEL.model_id],
    pro: [MODEL.model_id],
  },
  surface_defaults: {
    baseline: DEFAULTS,
    mid: DEFAULTS,
    pro: DEFAULTS,
  },
};

function envelope(
  body: ModelManifestBodyV2 = BODY,
  domain = MODEL_MANIFEST_V2_DOMAIN,
): SignedModelManifestV2 {
  const message = new TextEncoder().encode(
    domain + MODEL_MANIFEST_V2_DELIMITER + canonicalJson(body),
  );
  return {
    body,
    signature: toBase64url(ed25519.sign(message, PRIVATE_KEY)),
  };
}

function text(body = BODY, domain = MODEL_MANIFEST_V2_DOMAIN): string {
  return JSON.stringify(envelope(body, domain));
}

function refusal(input: string | null): string {
  const result = verifyModelManifestV2WithKey(input, PUBLIC_KEY);
  expect(result.ok).toBe(false);
  return result.ok ? "unexpected_ok" : result.reason;
}

function binding(surface: (typeof SURFACES)[number]) {
  return {
    model_id: MODEL.model_id,
    runtime_tag: "qwen2.5:1.5b",
    ollama_identity: MODEL.ollama_identity,
    assurance: IMMUNE_MODEL_LOAD_SURFACES.includes(
      surface as (typeof IMMUNE_MODEL_LOAD_SURFACES)[number],
    ) ? "immune" as const : "light" as const,
    manifest_version: BODY.manifest_version,
  };
}

function state(): LocalIntegrityStateV2 {
  const signed = envelope();
  return {
    state: "armed",
    schema_version: 2,
    manifest_version_floor: BODY.manifest_version,
    signed_manifest: signed,
    signed_body_sha256: computeModelManifestV2BodyDigest(BODY),
    ollama_models_root: "/var/lib/ollama/models",
    bindings: {
      concierge: binding("concierge"),
      "sentinel-scoring": binding("sentinel-scoring"),
    },
    committed_at: "2026-08-25T08:00:00.000Z",
  };
}

describe("Q5A V2 model-load-integrity contract", () => {
  it("freezes the non-overlapping V2 domain and inert public barrel", () => {
    expect(MODEL_MANIFEST_V2_DOMAIN).toBe("sanctuary.model-manifest.v2");
    expect(MODEL_MANIFEST_V2_DOMAIN).not.toBe(MODEL_MANIFEST_DOMAIN);
    expect(MODEL_MANIFEST_V2_SCHEMA_VERSION).toBe(2);
    expect(MODEL_MANIFEST_V2_DELIMITER).toBe("\n");
    expect(intelligence.verifyModelManifestV2WithKey).toBe(verifyModelManifestV2WithKey);
    expect(IMMUNE_MODEL_LOAD_SURFACES).toEqual([
      "sentinel-scoring",
      "privacy-filter-tier-2",
    ]);
  });

  it("verifies the exact V2 signature framing and canonical body digest", () => {
    const result = verifyModelManifestV2WithKey(text(), PUBLIC_KEY);
    expect(result.ok).toBe(true);
    expect(Buffer.from(buildModelManifestV2Message(BODY)).toString("utf8")).toBe(
      MODEL_MANIFEST_V2_DOMAIN + "\n" + canonicalJson(BODY),
    );
    expect(computeModelManifestV2BodyDigest(BODY)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("freezes a cross-language canonicalization and Ed25519 vector", () => {
    expect(VECTOR.domain).toBe(MODEL_MANIFEST_V2_DOMAIN);
    expect(Buffer.from(MODEL_MANIFEST_V2_DELIMITER).toString("hex")).toBe(VECTOR.delimiter_hex);
    expect(VECTOR.body).toEqual(BODY);
    expect(computeModelManifestV2BodyDigest(BODY)).toBe(VECTOR.body_sha256);
    expect(toBase64url(PUBLIC_KEY)).toBe(VECTOR.public_key_b64url);
    expect(envelope().signature).toBe(VECTOR.signature_b64url);
  });

  it("refuses V1-domain signatures and schema downgrade", () => {
    expect(refusal(text(BODY, MODEL_MANIFEST_DOMAIN))).toBe("bad_signature");
    const downgraded = structuredClone(BODY) as unknown as { schema_version: number };
    downgraded.schema_version = 1;
    expect(refusal(text(downgraded as ModelManifestBodyV2))).toBe("downgrade");
    const future = structuredClone(BODY) as unknown as { schema_version: number };
    future.schema_version = 3;
    expect(refusal(text(future as ModelManifestBodyV2))).toBe("invalid_value");
  });

  it("refuses duplicate, prototype, missing, unknown, and oversized input", () => {
    expect(refusal(text().replace('"schema_version":2', '"schema_version":2,"schema_version":2')))
      .toBe("duplicate_key");
    expect(refusal(text().replace('"schema_version":2', '"__proto__":{},"schema_version":2')))
      .toBe("prototype_key");
    const missing = JSON.parse(text()) as Record<string, unknown>;
    delete (missing.body as Record<string, unknown>).tiers;
    expect(refusal(JSON.stringify(missing))).toBe("missing_key");
    const unknown = JSON.parse(text()) as { body: Record<string, unknown> };
    unknown.body.weights_sha256 = DIGEST;
    expect(refusal(JSON.stringify(unknown))).toBe("unknown_key");
    expect(refusal(" ".repeat(256 * 1024 + 1))).toBe("manifest_too_large");
  });

  it("refuses zero keys/signatures, bad signatures, and rollback floors", () => {
    expect(verifyModelManifestV2WithKey(text(), new Uint8Array(32))).toEqual({
      ok: false,
      reason: "zero_pinned_key",
    });
    const zero = envelope();
    zero.signature = toBase64url(new Uint8Array(64));
    expect(refusal(JSON.stringify(zero))).toBe("zero_signature");
    const tampered = JSON.parse(text()) as { body: { manifest_version: number } };
    tampered.body.manifest_version = 10;
    expect(refusal(JSON.stringify(tampered))).toBe("bad_signature");
    expect(verifyModelManifestV2WithKey(text(), PUBLIC_KEY, { manifestVersionFloor: 10 }))
      .toEqual({ ok: false, reason: "rollback" });
  });

  it("derives exact explicit runtime tags and manifest paths", () => {
    expect(deriveOllamaRuntimeTag(MODEL.ollama_identity)).toBe("qwen2.5:1.5b");
    expect(deriveOllamaManifestRelativePath(MODEL.ollama_identity)).toBe(
      "manifests/registry.ollama.ai/library/qwen2.5/1.5b",
    );
    const namespaced = {
      ...MODEL.ollama_identity,
      namespace: "acme",
    };
    expect(deriveOllamaRuntimeTag(namespaced)).toBe("acme/qwen2.5:1.5b");
  });

  it.each([
    ["implicit latest", { tag: "" }],
    ["separator", { namespace: "library/escape" }],
    ["uppercase", { model: "Qwen" }],
    ["unicode", { tag: "one∕two" }],
    ["zero digest", { ollama_manifest_sha256: "0".repeat(64) }],
  ])("refuses invalid signed Ollama identity: %s", (_label, patch) => {
    const body = structuredClone(BODY);
    body.models[MODEL.model_id]!.ollama_identity = {
      ...body.models[MODEL.model_id]!.ollama_identity,
      ...patch,
    };
    expect(refusal(text(body))).toBe("invalid_value");
  });

  it("refuses one runtime tag bound to conflicting manifest digests", () => {
    const body = structuredClone(BODY);
    body.models["qwen2.5-1.5b-conflict"] = {
      ...structuredClone(MODEL),
      model_id: "qwen2.5-1.5b-conflict",
      ollama_identity: {
        ...MODEL.ollama_identity,
        ollama_manifest_sha256: "2".repeat(64),
      },
    };
    for (const tier of ["baseline", "mid", "pro"] as const) {
      (body.tiers[tier] as string[]).push("qwen2.5-1.5b-conflict");
    }
    expect(refusal(text(body))).toBe("invalid_reference");
  });

  it("validates and rederives an exact armed record", () => {
    const result = validateLocalIntegrityStateV2(state(), PUBLIC_KEY);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.state.bindings.concierge?.assurance).toBe("light");
    expect(result.state.bindings["sentinel-scoring"]?.assurance).toBe("immune");
    expect(result.state.signed_body_sha256).toBe(computeModelManifestV2BodyDigest(BODY));
  });

  it("rejects stripped, tampered, downgraded, and mismatched armed records", () => {
    const stripped = structuredClone(state()) as unknown as { signed_manifest?: unknown };
    delete stripped.signed_manifest;
    expect(validateLocalIntegrityStateV2(stripped, PUBLIC_KEY)).toEqual({
      ok: false,
      reason: "integrity_state_invalid",
    });

    const wrongDigest = state();
    wrongDigest.signed_body_sha256 = "2".repeat(64);
    expect(validateLocalIntegrityStateV2(wrongDigest, PUBLIC_KEY)).toEqual({
      ok: false,
      reason: "integrity_state_invalid",
    });

    const wrongTag = state();
    wrongTag.bindings.concierge!.runtime_tag = "qwen2.5:latest";
    expect(validateLocalIntegrityStateV2(wrongTag, PUBLIC_KEY)).toEqual({
      ok: false,
      reason: "binding_mismatch",
    });

    const downgraded = state();
    downgraded.manifest_version_floor += 1;
    expect(validateLocalIntegrityStateV2(downgraded, PUBLIC_KEY)).toEqual({
      ok: false,
      reason: "rollback",
    });

    const noBindings = state();
    noBindings.bindings = {};
    expect(validateLocalIntegrityStateV2(noBindings, PUBLIC_KEY)).toEqual({
      ok: false,
      reason: "integrity_state_invalid",
    });
  });

  it("refuses immune downgrade, light escalation, unknown surface, and relative root", () => {
    const immuneDowngrade = state();
    immuneDowngrade.bindings["sentinel-scoring"]!.assurance = "light";
    expect(validateLocalIntegrityStateV2(immuneDowngrade, PUBLIC_KEY)).toEqual({
      ok: false,
      reason: "binding_mismatch",
    });

    const lightEscalation = state();
    lightEscalation.bindings.concierge!.assurance = "immune";
    expect(validateLocalIntegrityStateV2(lightEscalation, PUBLIC_KEY)).toEqual({
      ok: false,
      reason: "binding_mismatch",
    });

    const unknown = state() as LocalIntegrityStateV2 & {
      bindings: Record<string, unknown>;
    };
    unknown.bindings["future-surface"] = binding("concierge");
    expect(validateLocalIntegrityStateV2(unknown, PUBLIC_KEY)).toEqual({
      ok: false,
      reason: "integrity_state_invalid",
    });

    const relative = state();
    relative.ollama_models_root = "models";
    expect(validateLocalIntegrityStateV2(relative, PUBLIC_KEY)).toEqual({
      ok: false,
      reason: "model_root_invalid",
    });
  });

  it("remains inert: contract module exposes no I/O or activation verbs", () => {
    const exported = Object.keys(intelligence).filter((name) => name.includes("ManifestV2"));
    expect(exported).toEqual(expect.arrayContaining([
      "buildModelManifestV2Message",
      "computeModelManifestV2BodyDigest",
      "parseModelManifestV2Json",
      "verifyModelManifestV2WithKey",
    ]));
    expect(exported.some((name) => /fetch|pull|install|activate|write/i.test(name))).toBe(false);
  });
});
