import { ed25519 } from "@noble/curves/ed25519";
import { mkdir, mkdtemp, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { toBase64url } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { InMemoryModelProvenanceStore } from "../../src/operational/model-provenance.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { IntelligenceConfigStore } from "../../src/intelligence/policy-store.js";
import type { ModelManifestBodyV2 } from "../../src/intelligence/model-manifest-v2.js";
import { SURFACES } from "../../src/intelligence/types.js";
import {
  resolveOllamaModelsRoot,
  runLocalIntelligenceSetup,
} from "../../src/wrap/local-intelligence.js";
import type { OllamaClient } from "../../src/intelligence/substrates/local.js";
import { canonicalJson } from "../../src/v1/operator-signed.js";

const PRIVATE_KEY = new Uint8Array(32).fill(27);
const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY);
const DIGEST = "1".repeat(64);

function signedV2Fixture(): string {
  const modelId = "qwen2.5-1.5b";
  const defaults = Object.fromEntries(SURFACES.map((surface) => [
    surface,
    surface === "gate-explanation" ? null : modelId,
  ]));
  const body: ModelManifestBodyV2 = {
    schema_version: 2,
    manifest_version: 9,
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

function fixture() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const client = {
    pull: vi.fn(),
    show: vi.fn(),
  } as unknown as OllamaClient;
  return { storage, masterKey, auditLog, client };
}

describe("shared protect/init local-intelligence adapter", () => {
  it("normalizes an absolute configured root and rejects missing or unsupported roots", async () => {
    const parent = await realpath(
      await mkdtemp(join(tmpdir(), "sanctuary-q5d-root-")),
    );
    try {
      const root = join(parent, "models");
      await mkdir(root);
      await expect(resolveOllamaModelsRoot(
        "darwin",
        { OLLAMA_MODELS: join(parent, "unused", "..", "models") },
      )).resolves.toBe(root);
      await expect(resolveOllamaModelsRoot(
        "darwin",
        { OLLAMA_MODELS: join(parent, "missing") },
      )).rejects.toMatchObject({ reason: "model_root_invalid" });
      await expect(resolveOllamaModelsRoot("win32", {}, parent))
        .rejects.toMatchObject({ reason: "immune_platform_unsupported" });
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  it("refuses a configured root symlink before persistence", async () => {
    const parent = await realpath(
      await mkdtemp(join(tmpdir(), "sanctuary-q5d-root-link-")),
    );
    try {
      const root = join(parent, "models");
      const linked = join(parent, "models-link");
      await mkdir(root);
      await symlink(root, linked);
      await expect(resolveOllamaModelsRoot(
        "darwin",
        { OLLAMA_MODELS: linked },
      )).rejects.toMatchObject({ reason: "symlink_refused" });
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  it("keeps production inert and audits manifest-unavailable without model mutation", async () => {
    const { storage, masterKey, auditLog, client } = fixture();
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "test-fortress",
      isTty: true,
      print: vi.fn(),
    }, { client, confirm: vi.fn() })).resolves.toEqual({
      kind: "refused",
      reason: "integrity_state_absent",
    });
    expect(client.pull).not.toHaveBeenCalled();
    expect(client.show).not.toHaveBeenCalled();
    const events = await auditLog.query({
      operation_type: INTEL_OPS.MODEL_PROVISION_REFUSED,
    });
    expect(events.entries.at(-1)?.details).toMatchObject({
      reason: "integrity_state_absent",
    });
  });

  it("skips the future manifest loader on non-TTY even with a positive flag", async () => {
    const { storage, masterKey, auditLog, client } = fixture();
    const loadManifest = vi.fn(async () => "must not load");
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "test-fortress",
      isTty: false,
      preAnswered: true,
      print: vi.fn(),
    }, { client, loadManifest, confirm: vi.fn() })).resolves.toEqual({
      kind: "refused",
      reason: "non_tty",
    });
    expect(loadManifest).not.toHaveBeenCalled();
    expect(client.pull).not.toHaveBeenCalled();
  });

  it("completes the injected V2 fixture path through atomic state and provenance", async () => {
    const { storage, masterKey, auditLog, client } = fixture();
    const modelStore = new InMemoryModelProvenanceStore();
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "test-fortress",
      isTty: true,
      print: vi.fn(),
    }, {
      client,
      loadManifest: async () => signedV2Fixture(),
      modelManifestV2PublicKey: PUBLIC_KEY,
      modelStore,
      resolveModelsRoot: async () => "/var/lib/ollama/models",
      probeHardware: async () => ({
        totalRamGb: 16,
        cpuArch: "apple-silicon-m2",
        tier: "baseline",
        recommendedLocalModel: "gemma-2-2b",
        ollamaReachable: true,
        ollamaModels: [],
      }),
      runtimeVerifier: {
        verify: async () => ({
          ok: true,
          state: "runtime_manifest_match",
          runtimeTag: "qwen2.5:1.5b",
          observedManifestDigest: DIGEST,
        }),
      },
      immuneVerifier: {
        verify: async () => ({
          ok: true,
          state: "immune_verified",
          runtimeTag: "qwen2.5:1.5b",
          expectedManifestDigest: DIGEST,
          descriptorCount: 2,
          bytesHashed: 10,
          verifiedArtifactDigests: ["2".repeat(64)],
          completedAtMonotonicMs: 1,
          cached: false,
        }),
      },
      confirm: vi.fn(),
    })).resolves.toMatchObject({
      kind: "already-provisioned",
      provenanceProjection: "projected",
    });
    expect(client.pull).not.toHaveBeenCalled();
    const loaded = await new IntelligenceConfigStore(
      storage,
      masterKey,
      { modelManifestV2PublicKey: PUBLIC_KEY },
    ).load();
    expect(loaded).toMatchObject({
      kind: "loaded",
      config: {
        version: 2,
        customLocalModelTags: { concierge: "qwen2.5:1.5b" },
        localIntegrityState: { manifest_version_floor: 9 },
      },
    });
    expect(modelStore.get("qwen2.5-1.5b")).toMatchObject({
      runtime_manifest_hash: `sha256:${DIGEST}`,
      load_integrity_assurance: "on-disk-all-layers",
    });
  });
});
