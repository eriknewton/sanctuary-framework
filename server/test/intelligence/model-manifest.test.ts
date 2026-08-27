import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { canonicalJson } from "../../src/v1/operator-signed.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import * as intelligenceBarrel from "../../src/intelligence/index.js";
import {
  MODEL_MANIFEST_DELIMITER,
  MODEL_MANIFEST_DOMAIN,
  MODEL_MANIFEST_MAX_JSON_CHARS,
  MODEL_MANIFEST_MAX_MODELS,
  MODEL_MANIFEST_MAX_MODELS_PER_TIER,
  MODEL_MANIFEST_MAX_PARAMS_B,
  MODEL_MANIFEST_MIN_PARAMS_B,
  MODEL_MANIFEST_TIERS,
  PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL,
  buildModelManifestMessage,
  parseModelManifestJson,
  provenanceFromVerifiedModelManifest,
  resolveModelForSurface,
  verifyModelManifestWithKey,
  type ModelManifestBody,
  type ModelManifestModel,
} from "../../src/intelligence/model-manifest.js";
import {
  SURFACES,
  TIER2_PINNED_SURFACE,
  isTier2PinViolation,
} from "../../src/intelligence/types.js";
import { PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL } from "../../src/release-manifest.js";

const PRIVATE_KEY = new Uint8Array(32).fill(7);
const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY);
const OTHER_PRIVATE_KEY = new Uint8Array(32).fill(11);
const OTHER_PUBLIC_KEY = ed25519.getPublicKey(OTHER_PRIVATE_KEY);
const FLOOR_HASH = "1".repeat(64);

const FLOOR_MODEL: ModelManifestModel = {
  model_id: "qwen2.5-1.5b",
  model_name: "Qwen2.5 1.5B Instruct",
  model_version: "2.5",
  provider: "Alibaba Cloud",
  runtime: "ollama",
  runtime_tag: "qwen2.5:1.5b",
  registry_source: "ollama://qwen2.5:1.5b",
  weights_sha256: FLOOR_HASH,
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

const BODY: ModelManifestBody = {
  manifest_version: 7,
  models: { [FLOOR_MODEL.model_id]: FLOOR_MODEL },
  tiers: {
    baseline: [FLOOR_MODEL.model_id],
    mid: [FLOOR_MODEL.model_id],
    pro: [FLOOR_MODEL.model_id],
  },
  surface_defaults: {
    baseline: {
      concierge: FLOOR_MODEL.model_id,
      "direct-agent-gate-advisor": FLOOR_MODEL.model_id,
      "sentinel-scoring": FLOOR_MODEL.model_id,
      "gate-explanation": null,
      "privacy-filter-tier-2": FLOOR_MODEL.model_id,
      "template-suggestion": FLOOR_MODEL.model_id,
    },
    mid: {
      concierge: FLOOR_MODEL.model_id,
      "direct-agent-gate-advisor": FLOOR_MODEL.model_id,
      "sentinel-scoring": FLOOR_MODEL.model_id,
      "gate-explanation": null,
      "privacy-filter-tier-2": FLOOR_MODEL.model_id,
      "template-suggestion": FLOOR_MODEL.model_id,
    },
    pro: {
      concierge: FLOOR_MODEL.model_id,
      "direct-agent-gate-advisor": FLOOR_MODEL.model_id,
      "sentinel-scoring": FLOOR_MODEL.model_id,
      "gate-explanation": null,
      "privacy-filter-tier-2": FLOOR_MODEL.model_id,
      "template-suggestion": FLOOR_MODEL.model_id,
    },
  },
};

function cloneBody(): ModelManifestBody {
  return structuredClone(BODY);
}

function signBody(
  body: ModelManifestBody,
  privateKey = PRIVATE_KEY,
  domain = MODEL_MANIFEST_DOMAIN,
  delimiter = MODEL_MANIFEST_DELIMITER,
): string {
  const message = stringToBytes(domain + delimiter + canonicalJson(body));
  return JSON.stringify({
    body,
    signature: toBase64url(ed25519.sign(message, privateKey)),
  });
}

function refusal(text: string | null, key = PUBLIC_KEY): string {
  const result = verifyModelManifestWithKey(text, key);
  expect(result.ok).toBe(false);
  return result.ok ? "unexpected_ok" : result.reason;
}

describe("signed local-model manifest contract", () => {
  it("freezes the domain, delimiter, release-key reuse, tiers, and barrel exports", () => {
    expect(MODEL_MANIFEST_DOMAIN).toBe("sanctuary.model-manifest.v1");
    expect(MODEL_MANIFEST_DELIMITER).toBe("\n");
    expect(PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL).toBe(
      PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL,
    );
    expect(MODEL_MANIFEST_TIERS).toEqual(["baseline", "mid", "pro"]);
    expect(intelligenceBarrel.MODEL_MANIFEST_DOMAIN).toBe(MODEL_MANIFEST_DOMAIN);
    expect(intelligenceBarrel.verifyModelManifestWithKey).toBe(
      verifyModelManifestWithKey,
    );
  });

  it("uses a deterministic signed vector and verifies every typed consumer", () => {
    const text = signBody(BODY);
    const parsed = parseModelManifestJson(text);
    expect(parsed.ok).toBe(true);
    const result = verifyModelManifestWithKey(text, PUBLIC_KEY);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const model = resolveModelForSurface(
      result.body,
      "baseline",
      "privacy-filter-tier-2",
    );
    expect(model?.model_id).toBe(FLOOR_MODEL.model_id);
    expect(
      provenanceFromVerifiedModelManifest(
        model!,
        "2026-08-24T00:00:00.000Z",
      ),
    ).toEqual({
      model_id: FLOOR_MODEL.model_id,
      model_name: FLOOR_MODEL.model_name,
      model_version: FLOOR_MODEL.model_version,
      provider: FLOOR_MODEL.provider,
      runtime_manifest_hash: `sha256:${FLOOR_HASH}`,
      license: "Apache-2.0",
      open_weights: true,
      open_source: false,
      local_inference: true,
      declared_at: "2026-08-24T00:00:00.000Z",
    });
  });

  it("canonicalizes object key order without changing the signed meaning", () => {
    const reordered: ModelManifestBody = {
      surface_defaults: BODY.surface_defaults,
      tiers: BODY.tiers,
      models: BODY.models,
      manifest_version: BODY.manifest_version,
    };
    const signature = ed25519.sign(buildModelManifestMessage(BODY), PRIVATE_KEY);
    const text = JSON.stringify({
      signature: toBase64url(signature),
      body: reordered,
    });
    expect(verifyModelManifestWithKey(text, PUBLIC_KEY).ok).toBe(true);
  });

  it("refuses the same body signed under a wrong domain", () => {
    expect(refusal(signBody(BODY, PRIVATE_KEY, "sanctuary.release-manifest.v1"))).toBe(
      "bad_signature",
    );
  });

  it("refuses the same body signed without the frozen delimiter", () => {
    expect(refusal(signBody(BODY, PRIVATE_KEY, MODEL_MANIFEST_DOMAIN, ""))).toBe(
      "bad_signature",
    );
  });

  it("refuses cross-domain release-manifest input", () => {
    expect(
      refusal(
        JSON.stringify({
          body: { version: "1.7.2", artifact_hashes: {} },
          signature: toBase64url(new Uint8Array(64).fill(1)),
        }),
      ),
    ).toBe("unknown_key");
  });

  it("refuses absent, malformed, non-object, and unsigned input", () => {
    expect(refusal(null)).toBe("absent");
    expect(refusal("{")).toBe("malformed_json");
    expect(refusal("[]")).toBe("invalid_type");
    expect(refusal(JSON.stringify({ body: BODY }))).toBe("missing_key");
  });

  it("refuses duplicate semantic keys before signature verification", () => {
    const duplicate = signBody(BODY).replace(
      '"manifest_version":7',
      '"manifest_version":7,"manifest_version":7',
    );
    expect(refusal(duplicate)).toBe("duplicate_key");
  });

  it("refuses prototype-pollution keys", () => {
    const polluted = signBody(BODY).replace(
      '"manifest_version":7',
      '"__proto__":{},"manifest_version":7',
    );
    expect(refusal(polluted)).toBe("prototype_key");
  });

  it("distinguishes missing and unknown exact-schema keys", () => {
    const missing = cloneBody() as unknown as Record<string, unknown>;
    delete missing.models;
    expect(refusal(signBody(missing as unknown as ModelManifestBody))).toBe("missing_key");

    const unknown = cloneBody() as ModelManifestBody & { authority?: string };
    unknown.authority = "manifest-may-change-substrate";
    expect(refusal(signBody(unknown))).toBe("unknown_key");
  });

  it("refuses non-canonical strict base64url", () => {
    const parsed = JSON.parse(signBody(BODY)) as { body: unknown; signature: string };
    parsed.signature += "=";
    expect(refusal(JSON.stringify(parsed))).toBe("bad_signature_encoding");
  });

  it("refuses wrong signature lengths", () => {
    const shortSignature = JSON.stringify({
      body: BODY,
      signature: toBase64url(new Uint8Array(63).fill(1)),
    });
    expect(refusal(shortSignature)).toBe("bad_signature_length");
  });

  it("refuses all-zero signature material", () => {
    const zeroSignature = JSON.stringify({
      body: BODY,
      signature: toBase64url(new Uint8Array(64)),
    });
    expect(refusal(zeroSignature)).toBe("zero_signature");
  });

  it("refuses wrong-length and all-zero public keys", () => {
    expect(refusal(signBody(BODY), new Uint8Array(31))).toBe(
      "bad_pinned_key_length",
    );
    expect(refusal(signBody(BODY), new Uint8Array(32))).toBe("zero_pinned_key");
  });

  it("refuses wrong-key and tampered signatures", () => {
    expect(refusal(signBody(BODY), OTHER_PUBLIC_KEY)).toBe("bad_signature");
    const tampered = JSON.parse(signBody(BODY)) as {
      body: ModelManifestBody;
      signature: string;
    };
    tampered.body.manifest_version += 1;
    expect(refusal(JSON.stringify(tampered))).toBe("bad_signature");
  });

  it("refuses invalid and all-zero SHA-256 values", () => {
    for (const digest of ["a".repeat(63), "A".repeat(64), "0".repeat(64)]) {
      const body = cloneBody();
      body.models[FLOOR_MODEL.model_id]!.weights_sha256 = digest;
      expect(refusal(signBody(body))).toBe("invalid_value");
    }
  });

  it("refuses non-finite or out-of-range parameter sizes", () => {
    for (const params of [
      MODEL_MANIFEST_MIN_PARAMS_B / 2,
      MODEL_MANIFEST_MAX_PARAMS_B + 1,
    ]) {
      const body = cloneBody();
      body.models[FLOOR_MODEL.model_id]!.params_b = params;
      expect(refusal(signBody(body))).toBe("invalid_value");
    }
    const infinity = signBody(BODY).replace('"params_b":1.5', '"params_b":1e9999');
    expect(refusal(infinity)).toBe("malformed_json");
  });

  it("refuses bounded strings and oversized serialized input", () => {
    const body = cloneBody();
    body.models[FLOOR_MODEL.model_id]!.model_name = "x".repeat(257);
    expect(refusal(signBody(body))).toBe("invalid_value");
    expect(refusal(" ".repeat(MODEL_MANIFEST_MAX_JSON_CHARS + 1))).toBe(
      "manifest_too_large",
    );
  });

  it("caps model records before traversing them", () => {
    const body = cloneBody();
    body.models = {};
    for (let index = 0; index <= MODEL_MANIFEST_MAX_MODELS; index += 1) {
      const id = `model-${index}`;
      body.models[id] = {
        ...structuredClone(FLOOR_MODEL),
        model_id: id,
        runtime_tag: id,
        registry_source: `ollama://${id}`,
      };
    }
    expect(refusal(signBody(body))).toBe("collection_too_large");
  });

  it("caps tier collections before traversing their members", () => {
    const body = cloneBody();
    body.tiers.baseline = Array.from(
      { length: MODEL_MANIFEST_MAX_MODELS_PER_TIER + 1 },
      () => FLOOR_MODEL.model_id,
    );
    expect(refusal(signBody(body))).toBe("collection_too_large");
  });

  it("refuses unknown, duplicate, and unassigned tier model references", () => {
    const unknown = cloneBody();
    unknown.tiers.baseline = ["unknown-model"];
    expect(refusal(signBody(unknown))).toBe("invalid_reference");

    const duplicate = cloneBody();
    duplicate.tiers.baseline = [FLOOR_MODEL.model_id, FLOOR_MODEL.model_id];
    expect(refusal(signBody(duplicate))).toBe("invalid_reference");

    const unassigned = cloneBody();
    unassigned.models.extra = {
      ...structuredClone(FLOOR_MODEL),
      model_id: "extra",
      runtime_tag: "extra",
      registry_source: "ollama://extra",
    };
    expect(refusal(signBody(unassigned))).toBe("invalid_reference");
  });

  it("refuses unknown and wrong-tier surface-default references", () => {
    const unknown = cloneBody();
    unknown.surface_defaults.baseline.concierge = "unknown-model";
    expect(refusal(signBody(unknown))).toBe("invalid_reference");

    const wrongTier = cloneBody();
    wrongTier.models.extra = {
      ...structuredClone(FLOOR_MODEL),
      model_id: "extra",
      runtime_tag: "extra",
      registry_source: "ollama://extra",
    };
    wrongTier.tiers.mid = [FLOOR_MODEL.model_id, "extra"];
    wrongTier.tiers.pro = [FLOOR_MODEL.model_id, "extra"];
    wrongTier.surface_defaults.baseline.concierge = "extra";
    expect(refusal(signBody(wrongTier))).toBe("invalid_reference");
  });

  it("requires every one of the six closed surfaces", () => {
    expect(SURFACES).toEqual([
      "concierge",
      "direct-agent-gate-advisor",
      "sentinel-scoring",
      "gate-explanation",
      "privacy-filter-tier-2",
      "template-suggestion",
    ]);
    for (const surface of SURFACES) {
      const body = cloneBody();
      delete (body.surface_defaults.baseline as Partial<Record<string, unknown>>)[
        surface
      ];
      expect(refusal(signBody(body))).toBe("missing_key");
    }
  });

  it("refuses duplicate and unknown surface keys", () => {
    const duplicate = signBody(BODY).replace(
      `"concierge":"${FLOOR_MODEL.model_id}"`,
      `"concierge":"${FLOOR_MODEL.model_id}","concierge":"${FLOOR_MODEL.model_id}"`,
    );
    expect(refusal(duplicate)).toBe("duplicate_key");

    const unknown = cloneBody();
    (unknown.surface_defaults.baseline as Record<string, string | null>).other =
      FLOOR_MODEL.model_id;
    expect(refusal(signBody(unknown))).toBe("unknown_key");
  });

  it("refuses unsafe or model-mismatched upstream registry sources", () => {
    for (const source of [
      "https://registry.ollama.ai/qwen2.5:1.5b",
      "ollama://../qwen2.5:1.5b",
      "ollama://qwen2.5:1.5b?digest=ignored",
      "ollama://other:latest",
    ]) {
      const body = cloneBody();
      body.models[FLOOR_MODEL.model_id]!.registry_source = source;
      expect(refusal(signBody(body))).toBe("unsafe_registry_source");
    }
  });

  it("refuses license and open-weights contradictions", () => {
    const notOpenWeights = cloneBody();
    notOpenWeights.models[FLOOR_MODEL.model_id]!.open_weights = false;
    notOpenWeights.models[FLOOR_MODEL.model_id]!.open_source = true;
    expect(refusal(signBody(notOpenWeights))).toBe("license_contradiction");

    const notOsi = cloneBody();
    notOsi.models[FLOOR_MODEL.model_id]!.open_source = true;
    notOsi.models[FLOOR_MODEL.model_id]!.license.osi_approved = false;
    expect(refusal(signBody(notOsi))).toBe("license_contradiction");

    const unknownOsi = cloneBody();
    unknownOsi.models[FLOOR_MODEL.model_id]!.license.identifier = "unknown";
    expect(refusal(signBody(unknownOsi))).toBe("license_contradiction");
  });

  it("accepts equal and higher versions but refuses a lower rollback", () => {
    const text = signBody(BODY);
    expect(
      verifyModelManifestWithKey(text, PUBLIC_KEY, {
        lastVerifiedManifestVersion: BODY.manifest_version,
      }).ok,
    ).toBe(true);
    expect(
      verifyModelManifestWithKey(text, PUBLIC_KEY, {
        lastVerifiedManifestVersion: BODY.manifest_version - 1,
      }).ok,
    ).toBe(true);
    const rollback = verifyModelManifestWithKey(text, PUBLIC_KEY, {
      lastVerifiedManifestVersion: BODY.manifest_version + 1,
    });
    expect(rollback).toEqual({ ok: false, reason: "rollback" });
  });

  it("refuses invalid injected anti-rollback floors", () => {
    for (const floor of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(
        verifyModelManifestWithKey(signBody(BODY), PUBLIC_KEY, {
          lastVerifiedManifestVersion: floor,
        }),
      ).toEqual({ ok: false, reason: "invalid_version_floor" });
    }
  });

  it("keeps the privacy-filter-tier-2 substrate pin independent of manifest data", () => {
    expect(TIER2_PINNED_SURFACE).toBe("privacy-filter-tier-2");
    expect(isTier2PinViolation(TIER2_PINNED_SURFACE, "venice")).toBe(true);
    expect(isTier2PinViolation(TIER2_PINNED_SURFACE, "frontier-with-filter")).toBe(
      true,
    );
    expect(isTier2PinViolation(TIER2_PINNED_SURFACE, "local")).toBe(false);
    expect(Object.keys(BODY.surface_defaults.baseline)).toEqual(SURFACES);
  });
});
