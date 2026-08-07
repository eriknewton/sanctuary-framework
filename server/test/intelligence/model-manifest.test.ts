import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  buildModelManifestMessage,
  MODEL_MANIFEST_DOMAIN,
  PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL,
  provenanceFromModelManifestModel,
  resolveModelForSurface,
  verifyModelManifest,
  verifyModelManifestWithKey,
  type ModelManifestBody,
  type SignedModelManifest,
} from "../../src/intelligence/model-manifest.js";
import { PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL } from "../../src/release-manifest.js";

const QWEN_HASH =
  "1111111111111111111111111111111111111111111111111111111111111111";
const PHI_HASH =
  "2222222222222222222222222222222222222222222222222222222222222222";

const BODY: ModelManifestBody = {
  manifest_version: 7,
  models: {
    "qwen2.5-1.5b": {
      model_id: "qwen2.5-1.5b",
      model_name: "Qwen2.5 1.5B Instruct",
      model_version: "2.5",
      provider: "Alibaba Cloud",
      runtime: "ollama",
      runtime_tag: "qwen2.5:1.5b",
      registry_source: "ollama://qwen2.5:1.5b",
      weights_sha256: QWEN_HASH,
      params_b: 1.5,
      license: "Apache-2.0",
      license_url: "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct",
      open_weights: true,
      open_source: false,
      local_inference: true,
    },
    "phi-4-mini": {
      model_id: "phi-4-mini",
      model_name: "Phi-4 Mini Instruct",
      model_version: "4",
      provider: "Microsoft",
      runtime: "ollama",
      runtime_tag: "phi4-mini",
      registry_source: "ollama://phi4-mini",
      weights_sha256: PHI_HASH,
      params_b: 3.8,
      license: "MIT",
      license_url: "https://huggingface.co/microsoft/Phi-4-mini-instruct",
      open_weights: true,
      open_source: false,
      local_inference: true,
    },
  },
  tiers: {
    baseline: ["qwen2.5-1.5b"],
    mid: ["qwen2.5-1.5b", "phi-4-mini"],
    pro: ["qwen2.5-1.5b", "phi-4-mini"],
  },
  surface_defaults: {
    baseline: {
      concierge: "qwen2.5-1.5b",
      "direct-agent-gate-advisor": "qwen2.5-1.5b",
      "sentinel-scoring": "qwen2.5-1.5b",
      "gate-explanation": null,
      "privacy-filter-tier-2": "qwen2.5-1.5b",
      "template-suggestion": "qwen2.5-1.5b",
    },
    mid: {
      concierge: "qwen2.5-1.5b",
      "direct-agent-gate-advisor": "qwen2.5-1.5b",
      "sentinel-scoring": "phi-4-mini",
      "gate-explanation": null,
      "privacy-filter-tier-2": "phi-4-mini",
      "template-suggestion": "qwen2.5-1.5b",
    },
    pro: {
      concierge: "qwen2.5-1.5b",
      "direct-agent-gate-advisor": "qwen2.5-1.5b",
      "sentinel-scoring": "phi-4-mini",
      "gate-explanation": null,
      "privacy-filter-tier-2": "phi-4-mini",
      "template-suggestion": "qwen2.5-1.5b",
    },
  },
};

function signManifest(
  body: ModelManifestBody,
  privateKey: Uint8Array,
): SignedModelManifest {
  const message = buildModelManifestMessage(body);
  const signature = ed25519.sign(message, privateKey);
  return { body, signature: toBase64url(signature) };
}

describe("model-manifest verifier", () => {
  it("uses a model-specific signing domain and the release signing key", () => {
    expect(MODEL_MANIFEST_DOMAIN).toBe("sanctuary.model-manifest.v1");
    expect(MODEL_MANIFEST_DOMAIN).not.toBe("sanctuary.release-manifest.v1");
    expect(PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL).toBe(
      PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL,
    );
  });

  it("verifies a correctly signed manifest, resolves surface defaults, and builds provenance", () => {
    const { publicKey, privateKey } = generateKeypair();
    const manifest = signManifest(BODY, privateKey);

    const result = verifyModelManifestWithKey(manifest, publicKey, {
      minimumManifestVersion: 6,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const immuneModel = resolveModelForSurface(
      result.body,
      "mid",
      "privacy-filter-tier-2",
    );
    expect(immuneModel?.model_id).toBe("phi-4-mini");
    expect(resolveModelForSurface(result.body, "baseline", "gate-explanation")).toBeNull();

    const provenance = provenanceFromModelManifestModel(
      result.body.models["phi-4-mini"]!,
      "2026-08-07T00:00:00.000Z",
    );
    expect(provenance).toMatchObject({
      model_id: "phi-4-mini",
      weights_hash: `sha256:${PHI_HASH}`,
      license: "MIT",
      open_weights: true,
      open_source: false,
      local_inference: true,
      declared_at: "2026-08-07T00:00:00.000Z",
    });
  });

  it("is order-independent over signed object keys", () => {
    const { publicKey, privateKey } = generateKeypair();
    const manifest = signManifest(BODY, privateKey);
    const reordered: SignedModelManifest = {
      signature: manifest.signature,
      body: {
        surface_defaults: BODY.surface_defaults,
        tiers: {
          pro: BODY.tiers.pro,
          mid: BODY.tiers.mid,
          baseline: BODY.tiers.baseline,
        },
        models: {
          "phi-4-mini": BODY.models["phi-4-mini"]!,
          "qwen2.5-1.5b": BODY.models["qwen2.5-1.5b"]!,
        },
        manifest_version: BODY.manifest_version,
      },
    };

    expect(verifyModelManifestWithKey(reordered, publicKey).ok).toBe(true);
  });

  it("rejects a tampered weights digest", () => {
    const { publicKey, privateKey } = generateKeypair();
    const manifest = signManifest(BODY, privateKey);
    const tampered: SignedModelManifest = {
      ...manifest,
      body: {
        ...BODY,
        models: {
          ...BODY.models,
          "qwen2.5-1.5b": {
            ...BODY.models["qwen2.5-1.5b"]!,
            weights_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
          },
        },
      },
    };

    const result = verifyModelManifestWithKey(tampered, publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature");
  });

  it("rejects a wrong-key signature", () => {
    const signer = generateKeypair();
    const other = generateKeypair();
    const manifest = signManifest(BODY, signer.privateKey);

    const result = verifyModelManifestWithKey(manifest, other.publicKey);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature");
  });

  it("rejects unsigned, missing-body, and non-object manifests as malformed", () => {
    const { publicKey } = generateKeypair();

    for (const candidate of [
      null,
      "nope",
      { body: BODY },
      { signature: "AAAA" },
    ]) {
      const result = verifyModelManifestWithKey(candidate, publicKey);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe("malformed");
    }
  });

  it("rejects non-canonical base64url signatures", () => {
    const { publicKey, privateKey } = generateKeypair();
    const manifest = signManifest(BODY, privateKey);
    expect(verifyModelManifestWithKey(manifest, publicKey).ok).toBe(true);

    const result = verifyModelManifestWithKey(
      { ...manifest, signature: `${manifest.signature}=` },
      publicKey,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("malformed");
  });

  it("rejects all-zero keys and all-zero signatures", () => {
    const { publicKey, privateKey } = generateKeypair();
    const manifest = signManifest(BODY, privateKey);

    const badKey = verifyModelManifestWithKey(manifest, new Uint8Array(32));
    expect(badKey.ok).toBe(false);
    if (!badKey.ok) expect(badKey.reason).toBe("bad_pinned_key");

    const badSignature = verifyModelManifestWithKey(
      { ...manifest, signature: toBase64url(new Uint8Array(64)) },
      publicKey,
    );
    expect(badSignature.ok).toBe(false);
    if (!badSignature.ok) expect(badSignature.reason).toBe("bad_signature");
  });

  it("rejects a correctly signed manifest below the anti-rollback floor", () => {
    const { publicKey, privateKey } = generateKeypair();
    const manifest = signManifest(BODY, privateKey);

    const result = verifyModelManifestWithKey(manifest, publicKey, {
      minimumManifestVersion: BODY.manifest_version + 1,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("stale_version");
  });

  it("rejects manifests whose signed references or schema are malformed", () => {
    const { publicKey, privateKey } = generateKeypair();
    const badBody = {
      ...BODY,
      surface_defaults: {
        ...BODY.surface_defaults,
        baseline: {
          ...BODY.surface_defaults.baseline,
          concierge: "missing-model",
        },
      },
    };
    const manifest = signManifest(badBody as ModelManifestBody, privateKey);

    const result = verifyModelManifestWithKey(manifest, publicKey);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("malformed");
  });

  it("runtime verification refuses a manifest signed by a non-pinned key", () => {
    const { privateKey } = generateKeypair();
    const manifest = signManifest(BODY, privateKey);

    const result = verifyModelManifest(manifest);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature");
  });
});
