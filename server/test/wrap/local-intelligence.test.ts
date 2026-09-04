import { ed25519 } from "@noble/curves/ed25519";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
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
import {
  PACKAGED_MODEL_MANIFEST_AUDIT_STAGE,
  PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256,
} from "../../src/intelligence/packaged-model-manifest.js";
import { SURFACES } from "../../src/intelligence/types.js";
import {
  resolveOllamaModelsRoot,
  runLocalIntelligenceSetup,
  type RunLocalIntelligenceSetupDeps,
} from "../../src/wrap/local-intelligence.js";
import type { OllamaClient } from "../../src/intelligence/substrates/local.js";
import { canonicalJson } from "../../src/v1/operator-signed.js";

const PRIVATE_KEY = new Uint8Array(32).fill(27);
const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY);
const DIGEST = "1".repeat(64);

function signedV2Fixture(manifestVersion = 9): string {
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

  // COMMITTED ASSET STATE (wired-consumer test, AGENTS.md rule 4). The real
  // composition root with no injected loader reaches the packaged-asset loader
  // and audits it. The tree carries a PLACEHOLDER envelope (all-zero
  // signature) until the coordinator signs; flip to "signed" in the change
  // that lands the signed asset. Each branch is strict for its state.
  const COMMITTED_ASSET_STATE = "signed" as "placeholder" | "signed";

  it("reaches the packaged signed-manifest loader by default and refuses with its typed reason", async () => {
    const { storage, masterKey, auditLog, client } = fixture();
    // The ceremony resolves the Ollama model root through the production
    // `OLLAMA_MODELS` input (same as `normalizes an absolute configured root`
    // above); a runner without ~/.ollama/models must still reach the loader
    // and then the operator decline, not stop at `model_root_invalid`.
    const parent = await realpath(await mkdtemp(join(tmpdir(), "sanctuary-q5f-wired-root-")));
    const modelsRoot = join(parent, "models");
    await mkdir(modelsRoot);
    const previousModelsEnv = process.env.OLLAMA_MODELS;
    process.env.OLLAMA_MODELS = modelsRoot;
    let result: Awaited<ReturnType<typeof runLocalIntelligenceSetup>>;
    try {
      result = await runLocalIntelligenceSetup({
        storage,
        masterKey,
        auditLog,
        identityId: "test-fortress",
        isTty: true,
        print: vi.fn(),
      }, {
        client,
        confirm: vi.fn(async () => false),
        probeHardware: async () => ({
          totalRamGb: 16,
          cpuArch: "apple-silicon-m2" as const,
          tier: "baseline" as const,
          recommendedLocalModel: "gemma-2-2b" as const,
          ollamaReachable: true,
          ollamaModels: [],
        }),
      });
    } finally {
      if (previousModelsEnv === undefined) delete process.env.OLLAMA_MODELS;
      else process.env.OLLAMA_MODELS = previousModelsEnv;
      await rm(parent, { recursive: true, force: true });
    }
    expect(client.pull).not.toHaveBeenCalled();
    expect(client.show).not.toHaveBeenCalled();
    const loadEvents = await auditLog.query({ operation_type: INTEL_OPS.LOAD_INTEGRITY });
    const loadRow = loadEvents.entries.find(
      (entry) => entry.details?.stage === PACKAGED_MODEL_MANIFEST_AUDIT_STAGE,
    );
    expect(loadRow?.details).toMatchObject({ source: "packaged" });
    const refusals = await auditLog.query({ operation_type: INTEL_OPS.MODEL_PROVISION_REFUSED });
    if (COMMITTED_ASSET_STATE === "placeholder") {
      expect(loadRow?.result).toBe("failure");
      expect(loadRow?.details).toMatchObject({
        reason: "integrity_asset_signature_invalid",
        detail: "zero_signature",
      });
      expect(result).toEqual({ kind: "refused", reason: "integrity_asset_signature_invalid" });
      expect(refusals.entries.at(-1)?.details).toMatchObject({
        reason: "integrity_asset_signature_invalid",
      });
    } else {
      expect(loadRow?.result).toBe("success");
      expect(loadRow?.details).toMatchObject({
        asset_sha256: PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256,
        manifest_version: 1,
      });
      // The loader verified the packaged manifest; the operator then declined.
      expect(result).toEqual({ kind: "refused", reason: "declined" });
    }
  });

  it("verifies an operator-supplied manifest path with the same loader and completes the ceremony", async () => {
    const parent = await mkdtemp(join(tmpdir(), "sanctuary-q5f-operator-"));
    try {
      const manifestPath = join(parent, "signed.json");
      await writeFile(manifestPath, signedV2Fixture(4));
      const { storage, masterKey, auditLog, client } = fixture();
      const deps = {
        client,
        modelManifestV2PublicKey: PUBLIC_KEY,
        resolveModelsRoot: async () => "/var/lib/ollama/models",
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
            runtimeTag: "qwen2.5:1.5b",
            observedManifestDigest: DIGEST,
          }),
        },
        immuneVerifier: {
          verify: async () => ({
            ok: true as const,
            state: "immune_verified" as const,
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
      } satisfies RunLocalIntelligenceSetupDeps;
      await expect(runLocalIntelligenceSetup({
        storage,
        masterKey,
        auditLog,
        identityId: "operator-path",
        isTty: true,
        modelManifestPath: manifestPath,
        print: vi.fn(),
      }, deps)).resolves.toMatchObject({ kind: "already-provisioned" });
      const loadEvents = await auditLog.query({ operation_type: INTEL_OPS.LOAD_INTEGRITY });
      expect(loadEvents.entries.find(
        (entry) => entry.details?.stage === PACKAGED_MODEL_MANIFEST_AUDIT_STAGE,
      )?.details).toMatchObject({ source: "operator-path", path: manifestPath, manifest_version: 4 });

      // A tampered operator file and a missing one are typed refusals of the
      // ceremony, never a fall back to the packaged asset.
      await writeFile(manifestPath, signedV2Fixture(5).replace('"manifest_version":5', '"manifest_version":6'));
      await expect(runLocalIntelligenceSetup({
        storage,
        masterKey,
        auditLog,
        identityId: "operator-path-tampered",
        isTty: true,
        modelManifestPath: manifestPath,
        print: vi.fn(),
      }, deps)).resolves.toEqual({ kind: "refused", reason: "integrity_asset_signature_invalid" });
      await expect(runLocalIntelligenceSetup({
        storage,
        masterKey,
        auditLog,
        identityId: "operator-path-missing",
        isTty: true,
        modelManifestPath: join(parent, "missing.json"),
        print: vi.fn(),
      }, deps)).resolves.toEqual({ kind: "refused", reason: "integrity_asset_absent" });
      expect(client.pull).not.toHaveBeenCalled();
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  it("does not read the manifest at all on non-TTY or explicit decline", async () => {
    const { storage, masterKey, auditLog, client } = fixture();
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "declined",
      isTty: true,
      preAnswered: false,
      print: vi.fn(),
    }, { client, confirm: vi.fn() })).resolves.toEqual({ kind: "refused", reason: "declined" });
    const loadEvents = await auditLog.query({ operation_type: INTEL_OPS.LOAD_INTEGRITY });
    expect(loadEvents.entries.filter(
      (entry) => entry.details?.stage === PACKAGED_MODEL_MANIFEST_AUDIT_STAGE,
    )).toHaveLength(0);
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
    const deps = {
      client,
      loadManifest: async () => signedV2Fixture(),
      modelManifestV2PublicKey: PUBLIC_KEY,
      modelStore,
      resolveModelsRoot: async () => "/var/lib/ollama/models",
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
          runtimeTag: "qwen2.5:1.5b",
          observedManifestDigest: DIGEST,
        }),
      },
      immuneVerifier: {
        verify: async () => ({
          ok: true as const,
          state: "immune_verified" as const,
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
    } satisfies RunLocalIntelligenceSetupDeps;
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "test-fortress",
      isTty: true,
      print: vi.fn(),
    }, deps)).resolves.toMatchObject({
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
    const projected = modelStore.get("qwen2.5-1.5b")!;
    expect(projected).toMatchObject({
      runtime_manifest_hash: `sha256:${DIGEST}`,
      load_integrity_assurance: "on-disk-all-layers",
    });
    modelStore.declare({
      ...projected,
      declared_at: "2000-01-01T00:00:00.000Z",
      load_integrity_verified_at: "2000-01-01T00:00:00.000Z",
    });
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "test-fortress-rerun",
      isTty: true,
      print: vi.fn(),
    }, deps)).resolves.toMatchObject({ kind: "already-provisioned" });
    const integrityEvents = await auditLog.query({
      operation_type: INTEL_OPS.LOAD_INTEGRITY,
    });
    expect(integrityEvents.entries.filter(
      (entry) => entry.details?.stage === "provenance_projection_recovery",
    )).toHaveLength(0);
  });

  it("reloads durable authority inside the lock before a stale-view ceremony can regress the floor", async () => {
    const { storage, masterKey, auditLog } = fixture();
    let resumeStaleCeremony!: (manifest: string) => void;
    const staleManifest = new Promise<string>((resolve) => {
      resumeStaleCeremony = resolve;
    });
    let staleLoadCompleted!: () => void;
    const staleLoad = new Promise<void>((resolve) => {
      staleLoadCompleted = resolve;
    });
    const commonDeps = {
      modelManifestV2PublicKey: PUBLIC_KEY,
      resolveModelsRoot: async () => "/var/lib/ollama/models",
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
          runtimeTag: "qwen2.5:1.5b",
          observedManifestDigest: DIGEST,
        }),
      },
      immuneVerifier: {
        verify: async () => ({
          ok: true as const,
          state: "immune_verified" as const,
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
    };
    const staleCeremony = runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "stale-floor-ceremony",
      isTty: true,
      print: vi.fn(),
    }, {
      ...commonDeps,
      loadManifest: async () => {
        staleLoadCompleted();
        return staleManifest;
      },
    });

    await staleLoad;
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "newer-floor-ceremony",
      isTty: true,
      print: vi.fn(),
    }, {
      ...commonDeps,
      loadManifest: async () => signedV2Fixture(9),
    })).resolves.toMatchObject({ kind: "already-provisioned" });

    resumeStaleCeremony(signedV2Fixture(8));
    await expect(staleCeremony).resolves.toEqual({
      kind: "refused",
      reason: "manifest_rollback",
    });
    const durable = await new IntelligenceConfigStore(
      storage,
      masterKey,
      { modelManifestV2PublicKey: PUBLIC_KEY },
    ).load();
    expect(durable).toMatchObject({
      kind: "loaded",
      config: {
        version: 2,
        localIntegrityState: { manifest_version_floor: 9 },
      },
    });
  });
});
