/**
 * Shared fixture for tests that need a REAL armed local-intelligence record:
 * a signed V2 catalog under a test key, plus the injected ceremony deps that
 * let `runLocalIntelligenceSetup` commit an armed record without a host,
 * network, or model store.
 *
 * One copy, because three tests that each hand-roll the manifest body drift
 * apart and then disagree about what "armed" looks like.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { vi } from "vitest";

import { toBase64url } from "../../../src/core/encoding.js";
import { canonicalJson } from "../../../src/v1/operator-signed.js";
import { SURFACES } from "../../../src/intelligence/types.js";
import type { ModelManifestBodyV2 } from "../../../src/intelligence/model-manifest-v2.js";
import type { OllamaClient } from "../../../src/intelligence/substrates/local.js";
import type { RunLocalIntelligenceSetupDeps } from "../../../src/wrap/local-intelligence.js";

/** Test catalog root. Never a real key: 32 identical bytes, seeded in source. */
const PRIVATE_KEY = new Uint8Array(32).fill(27);
export const CATALOG_PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY);
/** A second signer standing in for "this build does not trust that record". */
export const OTHER_CATALOG_PUBLIC_KEY = ed25519.getPublicKey(
  new Uint8Array(32).fill(31),
);
/** 64 hex characters = the sha256 digest width the V2 schema requires. */
export const FIXTURE_MANIFEST_DIGEST = "1".repeat(64);
export const FIXTURE_RUNTIME_TAG = "qwen2.5:1.5b";
export const FIXTURE_MANIFEST_VERSION = 9;

export function signedV2Fixture(
  manifestVersion = FIXTURE_MANIFEST_VERSION,
): string {
  const modelId = "qwen2.5-1.5b";
  const defaults = Object.fromEntries(SURFACES.map((surface) => [
    surface,
    surface === "gate-explanation" ? null : modelId,
  ]));
  const body: ModelManifestBodyV2 = {
    schema_version: 2,
    manifest_version: manifestVersion,
    models: {
      [modelId]: {
        model_id: modelId,
        model_name: "Qwen2.5 1.5B",
        model_version: "2.5",
        provider: "Alibaba Cloud",
        runtime: "ollama",
        ollama_identity: {
          registry: "registry.ollama.ai",
          namespace: "library",
          model: "qwen2.5",
          tag: "1.5b",
          ollama_manifest_sha256: FIXTURE_MANIFEST_DIGEST,
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
      },
    },
    tiers: { baseline: [modelId], mid: [modelId], pro: [modelId] },
    surface_defaults: {
      baseline: defaults,
      mid: defaults,
      pro: defaults,
    } as ModelManifestBodyV2["surface_defaults"],
  };
  const message = new TextEncoder().encode(
    `sanctuary.model-manifest.v2\n${canonicalJson(body)}`,
  );
  return JSON.stringify({
    body,
    signature: toBase64url(ed25519.sign(message, PRIVATE_KEY)),
  });
}

/** Injected ceremony deps: every host effect is a stub, nothing is pulled. */
export function armedCeremonyDeps(): RunLocalIntelligenceSetupDeps {
  return {
    client: { pull: vi.fn(), show: vi.fn() } as unknown as OllamaClient,
    loadManifest: async () => signedV2Fixture(),
    modelManifestV2PublicKey: CATALOG_PUBLIC_KEY,
    // Must match `LocalModelsRootResolution` in
    // ../../src/intelligence/provisioning.ts: the seam reports a resolution
    // state, never a bare path, so a caller cannot read "not resolved yet" as
    // a root. This fixture stands for an already-present, strictly resolved root.
    resolveModelsRoot: async () => ({
      kind: "resolved" as const,
      rootReal: "/var/lib/ollama/models",
    }),
    probeHardware: async () => ({
      totalRamGb: 16,
      cpuArch: "apple-silicon-m2" as const,
      tier: "baseline" as const,
      recommendedLocalModel: "gemma-2-2b" as const,
      ollamaReachable: true,
      ollamaModels: [],
    }),
    runtimeVerifier: {
      verify: async () => ({
        ok: true as const,
        state: "runtime_manifest_match" as const,
        runtimeTag: FIXTURE_RUNTIME_TAG,
        observedManifestDigest: FIXTURE_MANIFEST_DIGEST,
      }),
    },
    immuneVerifier: {
      verify: async () => ({
        ok: true as const,
        state: "immune_verified" as const,
        runtimeTag: FIXTURE_RUNTIME_TAG,
        expectedManifestDigest: FIXTURE_MANIFEST_DIGEST,
        descriptorCount: 2,
        bytesHashed: 10,
        verifiedArtifactDigests: ["2".repeat(64)],
        completedAtMonotonicMs: 1,
        cached: false,
      }),
    },
    confirm: vi.fn(),
  };
}
