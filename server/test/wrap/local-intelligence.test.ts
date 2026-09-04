import { ed25519 } from "@noble/curves/ed25519";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
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
  formatPullProgress,
  resolveOllamaModelsRootState,
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
      await expect(resolveOllamaModelsRootState(
        "darwin",
        { OLLAMA_MODELS: join(parent, "unused", "..", "models") },
      )).resolves.toEqual({ kind: "resolved", rootReal: root });
      await expect(resolveOllamaModelsRootState(
        "darwin",
        { OLLAMA_MODELS: join(parent, "missing") },
      )).rejects.toMatchObject({ reason: "model_root_invalid" });
      await expect(resolveOllamaModelsRootState("win32", {}, parent))
        .rejects.toMatchObject({ reason: "immune_platform_unsupported" });
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  it("reports an absent default root as no-models-yet but refuses an absent configured one", async () => {
    const parent = await realpath(
      await mkdtemp(join(tmpdir(), "sanctuary-q5d-fresh-host-")),
    );
    try {
      // A host where Ollama has never pulled has no ~/.ollama at all; the
      // runtime creates it on the first pull, so this is a deferred resolution
      // rather than a refusal.
      await expect(resolveOllamaModelsRootState("darwin", {}, parent))
        .resolves.toEqual({ kind: "default_root_absent" });
      await expect(resolveOllamaModelsRootState("darwin", { OLLAMA_MODELS: "" }, parent))
        .resolves.toEqual({ kind: "default_root_absent" });
      // An operator who named OLLAMA_MODELS asserted that exact path exists.
      await expect(resolveOllamaModelsRootState(
        "darwin",
        { OLLAMA_MODELS: join(parent, "explicit-missing") },
        parent,
      )).rejects.toMatchObject({ reason: "model_root_invalid" });
      // A path component that exists but is not a directory is a real
      // misconfiguration even under the default spelling.
      const blocked = await realpath(
        await mkdtemp(join(tmpdir(), "sanctuary-q5d-blocked-home-")),
      );
      await writeFile(join(blocked, ".ollama"), "not a directory");
      await expect(resolveOllamaModelsRootState("darwin", {}, blocked))
        .rejects.toMatchObject({ reason: "model_root_invalid" });
      await rm(blocked, { recursive: true, force: true });
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  it("refuses a model root that is group- or other-writable, or owned by another uid", async () => {
    const parent = await realpath(
      await mkdtemp(join(tmpdir(), "sanctuary-q5d-root-mode-")),
    );
    try {
      const root = join(parent, "models");
      await mkdir(root, { mode: 0o755 });
      // Baseline: an operator-owned, operator-only-writable root resolves.
      await expect(resolveOllamaModelsRootState("darwin", { OLLAMA_MODELS: root }))
        .resolves.toEqual({ kind: "resolved", rootReal: root });
      // The accepted root is persisted and trusted on every later run, so a
      // directory any other local process can write into is refused. This is
      // reachable now that an absent default root is created by the pull instead
      // of refused: a same-uid lower-privilege process can pre-create it.
      for (const mode of [0o775, 0o757, 0o777] as const) {
        await chmod(root, mode);
        await expect(resolveOllamaModelsRootState("darwin", { OLLAMA_MODELS: root }))
          .rejects.toMatchObject({ reason: "model_root_invalid" });
      }
      await chmod(root, 0o755);
      // A root owned by a different uid is refused even when its mode is tight.
      // The uid the resolver compares against is its last argument, which
      // production always supplies from the running process.
      const foreignUid = (process.getuid?.() ?? 0) + 1;
      await expect(
        resolveOllamaModelsRootState("darwin", { OLLAMA_MODELS: root }, undefined, foreignUid),
      ).rejects.toMatchObject({ reason: "model_root_invalid" });
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
      await expect(resolveOllamaModelsRootState(
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
        // After the loader verifies, the ceremony sweeps the runtime BEFORE the
        // operator confirm. The production runtime verifier talks to the local
        // Ollama endpoint; on a host without one, its connection failure is
        // `integrity_io_unavailable`, which is not repairable by a pull and
        // ends the ceremony before the decline. Inject the deterministic
        // "signed model not yet pulled" evidence so every platform reaches the
        // plan and the decline. The loader path under test is unchanged.
        runtimeVerifier: {
          verify: async (request) => ({
            ok: false as const,
            state: "tags_model_absent" as const,
            reason: "runtime_model_absent" as const,
            runtimeTag: request.binding.runtime_tag,
          }),
        },
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
        resolveModelsRoot: async () => ({ kind: "resolved" as const, rootReal: "/var/lib/ollama/models" }),
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

  it("leaves a headless run that never asked for local intelligence untouched", async () => {
    const { storage, masterKey, auditLog, client } = fixture();
    const loadManifest = vi.fn(async () => "must not load");
    const print = vi.fn();
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "unrequested",
      // A plain `sanctuary protect ...` in a script: no terminal, no flag.
      isTty: false,
      print,
    }, { client, loadManifest, confirm: vi.fn() })).resolves.toEqual({
      kind: "not-requested",
    });
    expect(loadManifest).not.toHaveBeenCalled();
    expect(client.pull).not.toHaveBeenCalled();
    expect(print).not.toHaveBeenCalled();
    // No refusal row: the operator never asked, so there is nothing to refuse.
    const refusals = await auditLog.query({
      operation_type: INTEL_OPS.MODEL_PROVISION_REFUSED,
    });
    expect(refusals.entries).toHaveLength(0);
    // And no durable record, so a later `intelligence diagnose` on a fresh
    // fortress reports absent rather than a persisted provisioning failure.
    expect(await storage.read("_intelligence", "substrate-config")).toBeNull();
  });

  it("still refuses non_tty out loud when the operator asked for the ceremony", async () => {
    const { storage, masterKey, auditLog, client } = fixture();
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "asked",
      isTty: false,
      preAnswered: true,
      print: vi.fn(),
    }, { client, confirm: vi.fn() })).resolves.toEqual({
      kind: "refused",
      reason: "non_tty",
    });
    const refusals = await auditLog.query({
      operation_type: INTEL_OPS.MODEL_PROVISION_REFUSED,
    });
    expect(refusals.entries.map((entry) => entry.details?.reason))
      .toContain("non_tty");
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
      resolveModelsRoot: async () => ({ kind: "resolved" as const, rootReal: "/var/lib/ollama/models" }),
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

  it("renders pull progress as one operator line per reported event", () => {
    expect(formatPullProgress("qwen2.5:1.5b", {
      status: `pulling sha256:${"1".repeat(64)}`,
      total: 400,
      completed: 100,
    })).toBe(`Pulling qwen2.5:1.5b: pulling ${"1".repeat(64)} 25%`);
    expect(formatPullProgress("qwen2.5:1.5b", { status: "pulling 0f4c8fab" }))
      .toBe("Pulling qwen2.5:1.5b: pulling 0f4c8fab");
    // No share is rendered when the runtime does not report both counters, or
    // reports counters that cannot be a share of a download.
    expect(formatPullProgress("qwen2.5:1.5b", { status: "pulling manifest" }))
      .toBe("Pulling qwen2.5:1.5b: pulling manifest");
    expect(formatPullProgress("qwen2.5:1.5b", {
      status: "verifying sha256 digest",
      total: 0,
      completed: 0,
    })).toBe("Pulling qwen2.5:1.5b: verifying sha256 digest");
    expect(formatPullProgress("qwen2.5:1.5b", {
      status: "success",
      total: 10,
      completed: 11,
    })).toBe("Pulling qwen2.5:1.5b: success");
  });

  it("never echoes a runtime-supplied status onto the operator's terminal", () => {
    // The status arrives from the Ollama process. A newline could forge a log
    // line, an ANSI escape could rewrite what is already on screen, and an
    // unbounded string could bury the surrounding output, so anything outside
    // the known forms renders as one fixed token.
    const hostile = "\u001b[2Kpulling manifest\nSanctuary: fortress armed\u0007";
    const rendered = formatPullProgress("qwen2.5:1.5b", { status: hostile });
    expect(rendered).toBe("Pulling qwen2.5:1.5b: runtime status");
    expect(rendered).not.toContain("\n");
    // eslint-disable-next-line no-control-regex
    expect(/[\u0000-\u001f\u007f]/.test(rendered)).toBe(false);
    expect(formatPullProgress("qwen2.5:1.5b", { status: "p".repeat(100 * 1024) }))
      .toBe("Pulling qwen2.5:1.5b: runtime status");
    // A digest-shaped status is reconstructed from the matched hex, so a status
    // that only starts like one cannot smuggle the rest through.
    expect(formatPullProgress("qwen2.5:1.5b", { status: "pulling 0f4c8f\u001b[31m" }))
      .toBe("Pulling qwen2.5:1.5b: runtime status");
    expect(formatPullProgress("qwen2.5:1.5b", { status: "pulling 0f4" }))
      .toBe("Pulling qwen2.5:1.5b: runtime status");
  });

  // WIRED-CONSUMER TEST (AGENTS.md rule 4): the ceremony's own pull seam must
  // hand the client a progress reporter that reaches the operator channel, or a
  // multi-gigabyte download reads as a hang no matter what the client emits.
  it("feeds streaming pull progress into the ceremony's operator channel", async () => {
    const { storage, masterKey, auditLog } = fixture();
    const printed: string[] = [];
    const client = {
      show: vi.fn(),
      pull: vi.fn(async (_tag: string, options?: {
        onProgress?: (progress: { status: string; total?: number; completed?: number }) => void;
      }) => {
        options?.onProgress?.({ status: "pulling manifest" });
        options?.onProgress?.({ status: "pulling 0f4c8fab", total: 1000, completed: 500 });
        options?.onProgress?.({ status: "success" });
        return { ok: true as const, failureClass: null };
      }),
    } as unknown as OllamaClient;
    const runtimeVerifier = {
      verify: vi.fn()
        .mockResolvedValueOnce({
          ok: false,
          state: "tags_model_absent",
          reason: "runtime_model_absent",
          runtimeTag: "qwen2.5:1.5b",
        })
        .mockResolvedValue({
          ok: true,
          state: "runtime_manifest_match",
          runtimeTag: "qwen2.5:1.5b",
          observedManifestDigest: DIGEST,
        }),
    };
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "pull-progress",
      isTty: true,
      print: (line) => printed.push(line),
    }, {
      client,
      modelManifestV2PublicKey: PUBLIC_KEY,
      loadManifest: async () => signedV2Fixture(9),
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
      runtimeVerifier,
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
      confirm: async () => true,
    })).resolves.toMatchObject({ kind: "provisioned" });
    expect(client.pull).toHaveBeenCalledWith(
      "qwen2.5:1.5b",
      expect.objectContaining({ onProgress: expect.any(Function) }),
    );
    // The first event and the terminal one always reach the operator; the middle
    // one is inside the rate-limit window, so it does not.
    expect(printed.filter((line) => line.startsWith("Pulling "))).toEqual([
      "Pulling qwen2.5:1.5b: pulling manifest",
      "Pulling qwen2.5:1.5b: success",
    ]);
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
      resolveModelsRoot: async () => ({ kind: "resolved" as const, rootReal: "/var/lib/ollama/models" }),
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
