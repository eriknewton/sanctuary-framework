// fail-before-exempt: Q5E residual 3 trims the dead `configVersion` field from the reloadAuthority mocks; the production contract never declared it, so this test-only cleanup has no fail-before behavior.
import { describe, expect, it, vi } from "vitest";
import { DEFAULT_PER_SURFACE } from "../../src/intelligence/defaults.js";
import {
  MODEL_REGISTRY_PROVIDER_CATEGORY,
  renderLocalProvisioningPlan,
  runLocalIntelligenceProvisioning,
  type AtomicLocalProvisioningCommit,
  type LocalProvisioningOps,
} from "../../src/intelligence/provisioning.js";
import type {
  LocalIntegrityStateV2,
  ModelManifestBodyV2,
  ModelManifestModelV2,
  SignedModelManifestV2,
} from "../../src/intelligence/model-manifest-v2.js";
import type { HardwareCapabilityReport, Surface } from "../../src/intelligence/types.js";
import { LocalIntegrityStateLoadError } from "../../src/intelligence/policy-store.js";
import { CrossProcessLockError } from "../../src/storage/cross-process-lock.js";

const HASH = "1".repeat(64);
const ROOT = "/var/lib/ollama/models";
const COMMITTED_AT = "2026-08-25T12:00:00.000Z";
const MODEL: ModelManifestModelV2 = {
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
    ollama_manifest_sha256: HASH,
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

const LOCAL_SURFACES = Object.entries(DEFAULT_PER_SURFACE)
  .filter(([, choice]) => choice === "local")
  .map(([surface]) => surface as Surface);

const defaults = Object.fromEntries(
  Object.keys(DEFAULT_PER_SURFACE).map((surface) => [
    surface,
    surface === "gate-explanation" ? null : MODEL.model_id,
  ]),
) as Record<Surface, string | null>;

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
    baseline: defaults,
    mid: defaults,
    pro: defaults,
  },
};

const MANIFEST: SignedModelManifestV2 = { body: BODY, signature: "fixture-signature" };

function runtimeSuccess() {
  return {
    ok: true as const,
    state: "runtime_manifest_match" as const,
    runtimeTag: "qwen2.5:1.5b",
    observedManifestDigest: HASH,
  };
}

function immuneSuccess() {
  return {
    ok: true as const,
    state: "immune_verified" as const,
    runtimeTag: "qwen2.5:1.5b",
    expectedManifestDigest: HASH,
    descriptorCount: 2,
    bytesHashed: 123,
    verifiedArtifactDigests: ["2".repeat(64), "3".repeat(64)],
    completedAtMonotonicMs: 42,
    cached: false,
  };
}

function makeOps(overrides: Partial<LocalProvisioningOps> = {}) {
  const sequence: string[] = [];
  const commits: AtomicLocalProvisioningCommit[] = [];
  const ops: LocalProvisioningOps = {
    isTty: true,
    platform: "darwin",
    manifestText: "signed V2 fixture",
    initialConfiguredChoices: { ...DEFAULT_PER_SURFACE },
    reloadAuthority: vi.fn(async () => ({
      configuredChoices: { ...DEFAULT_PER_SURFACE },
    })),
    verifyManifest: (_text, floor) =>
      floor !== undefined && BODY.manifest_version < floor
        ? { ok: false, reason: "rollback" }
        : { ok: true, body: BODY, manifest: MANIFEST },
    probeHardware: vi.fn(async () => ({
      totalRamGb: 16,
      cpuArch: "apple-silicon-m2",
      tier: "baseline",
      recommendedLocalModel: "gemma-2-2b",
      ollamaReachable: true,
      ollamaModels: [],
    } satisfies HardwareCapabilityReport)),
    resolveModelsRoot: vi.fn(async () => ROOT),
    runtimeVerifier: { verify: vi.fn(async () => runtimeSuccess()) },
    immuneVerifier: { verify: vi.fn(async () => immuneSuccess()) },
    withProvisioningLock: async (operation) => {
      sequence.push("lock-acquired");
      try {
        return await operation();
      } finally {
        sequence.push("lock-released");
      }
    },
    installRuntime: vi.fn(async () => true),
    pull: vi.fn(async () => {
      sequence.push("pull");
      return { ok: true, failureClass: null };
    }),
    confirm: vi.fn(async () => {
      sequence.push("confirm");
      return true;
    }),
    print: vi.fn(() => sequence.push("print")),
    commitVerified: vi.fn(async (commit) => {
      sequence.push("commit");
      commits.push(commit);
    }),
    projectProvenance: vi.fn(async () => {
      sequence.push("project");
    }),
    recordFailure: vi.fn(async () => undefined),
    audit: vi.fn(async () => undefined),
    now: () => new Date(COMMITTED_AT),
    ...overrides,
  };
  return { ops, sequence, commits };
}

function absentThenPresentVerifier() {
  return {
    verify: vi.fn()
      .mockResolvedValueOnce({
        ok: false,
        state: "tags_model_absent",
        reason: "runtime_model_absent",
        runtimeTag: "qwen2.5:1.5b",
      })
      .mockResolvedValue(runtimeSuccess()),
  };
}

describe("Q5D atomic local intelligence provisioning", () => {
  it("verifies every model, commits one complete record, then projects provenance", async () => {
    const { ops, sequence, commits } = makeOps({
      runtimeVerifier: absentThenPresentVerifier(),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toMatchObject({
      kind: "provisioned",
      surfaces: LOCAL_SURFACES,
      models: [MODEL.model_id],
      provenanceProjection: "projected",
    });
    expect(sequence.indexOf("confirm")).toBeLessThan(sequence.indexOf("pull"));
    expect(sequence.indexOf("commit")).toBeLessThan(sequence.indexOf("project"));
    expect(sequence.at(-1)).toBe("lock-released");
    expect(commits).toHaveLength(1);
    const commit = commits[0]!;
    expect(commit.integrityState).toMatchObject({
      state: "armed",
      schema_version: 2,
      manifest_version_floor: 9,
      signed_manifest: MANIFEST,
      ollama_models_root: ROOT,
      committed_at: COMMITTED_AT,
    });
    expect(Object.keys(commit.integrityState.bindings).sort()).toEqual(
      [...LOCAL_SURFACES].sort(),
    );
    expect(commit.runtimeTags.concierge).toBe("qwen2.5:1.5b");
    expect(commit.provenance[0]?.provenance).toMatchObject({
      runtime_manifest_hash: `sha256:${HASH}`,
      load_integrity_assurance: "on-disk-all-layers",
      model_manifest_version: 9,
    });
    expect(commit.provenance[0]?.provenance.weights_hash).toBeUndefined();
  });

  it("already-present exact matches skip consent and pull but perform the same atomic commit", async () => {
    const { ops, commits } = makeOps();
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toMatchObject({
      kind: "already-provisioned",
      provenanceProjection: "projected",
    });
    expect(ops.print).not.toHaveBeenCalled();
    expect(ops.confirm).not.toHaveBeenCalled();
    expect(ops.pull).not.toHaveBeenCalled();
    expect(ops.commitVerified).toHaveBeenCalledOnce();
    expect(ops.projectProvenance).toHaveBeenCalledWith(commits[0]!.provenance);
    expect(commits[0]!.integrityState.bindings.concierge?.runtime_tag)
      .toBe("qwen2.5:1.5b");
  });

  it("preserves old authority when the first verification crashes", async () => {
    const { ops } = makeOps({
      runtimeVerifier: { verify: vi.fn(async () => { throw new Error("crash-before-verify"); }) },
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "integrity_io_unavailable",
    });
    expect(ops.pull).not.toHaveBeenCalled();
    expect(ops.commitVerified).not.toHaveBeenCalled();
    expect(ops.projectProvenance).not.toHaveBeenCalled();
  });

  it("preserves old authority when verification crashes after one required model", async () => {
    const second = structuredClone(MODEL);
    second.model_id = "qwen2.5-1.5b-second";
    second.ollama_identity = {
      ...second.ollama_identity,
      model: "qwen2.5-second",
      ollama_manifest_sha256: "4".repeat(64),
    };
    const body = structuredClone(BODY);
    body.models[second.model_id] = second;
    for (const tier of ["baseline", "mid", "pro"] as const) {
      (body.tiers[tier] as string[]).push(second.model_id);
      body.surface_defaults[tier]["template-suggestion"] = second.model_id;
    }
    const runtimeVerifier = {
      verify: vi.fn()
        .mockResolvedValueOnce(runtimeSuccess())
        .mockRejectedValueOnce(new Error("crash-mid-verify")),
    };
    const { ops } = makeOps({
      verifyManifest: () => ({
        ok: true,
        body,
        manifest: { body, signature: "fixture" },
      }),
      runtimeVerifier,
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "integrity_io_unavailable",
    });
    expect(runtimeVerifier.verify).toHaveBeenCalledTimes(2);
    expect(ops.pull).not.toHaveBeenCalled();
    expect(ops.commitVerified).not.toHaveBeenCalled();
  });

  it.each([
    [new LocalIntegrityStateLoadError("manifest_rollback"), "manifest_rollback"],
    [new LocalIntegrityStateLoadError("binding_mismatch"), "binding_mismatch"],
    [new LocalIntegrityStateLoadError("integrity_state_invalid"), "integrity_state_invalid"],
    [new Error("atomic rename failed"), "integrity_io_unavailable"],
  ] as const)("surfaces authoritative commit refusal %s as %s", async (error, reason) => {
    const { ops } = makeOps({
      commitVerified: vi.fn(async () => { throw error; }),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason,
    });
    expect(ops.commitVerified).toHaveBeenCalledOnce();
    expect(ops.projectProvenance).not.toHaveBeenCalled();
    expect(ops.recordFailure).not.toHaveBeenCalled();
  });

  it("keeps committed Q5 authority when projection crashes and a later rerun repairs it", async () => {
    const first = makeOps({
      projectProvenance: vi.fn(async () => { throw new Error("projection crash"); }),
    });
    await expect(runLocalIntelligenceProvisioning(first.ops)).resolves.toMatchObject({
      kind: "already-provisioned",
      provenanceProjection: "degraded",
    });
    expect(first.ops.commitVerified).toHaveBeenCalledOnce();
    const recoveryAudit = vi.fn(async () => undefined);
    const recovery = makeOps({
      projectProvenance: vi.fn(async () => "repaired" as const),
      audit: recoveryAudit,
    });
    await expect(runLocalIntelligenceProvisioning(recovery.ops)).resolves.toMatchObject({
      kind: "already-provisioned",
      provenanceProjection: "projected",
    });
    expect(recovery.ops.projectProvenance).toHaveBeenCalledOnce();
    expect(recoveryAudit).toHaveBeenCalledWith(expect.objectContaining({
      operation: "intelligence_load_integrity",
      outcome: "success",
      details: expect.objectContaining({ stage: "provenance_projection_recovery" }),
    }));
  });

  it("reloads the floor under the lock before refusing a lower V2 input", async () => {
    const oldState = {
      manifest_version_floor: 10,
      ollama_models_root: ROOT,
    } as LocalIntegrityStateV2;
    const lockSpy = vi.fn();
    const withProvisioningLock: LocalProvisioningOps["withProvisioningLock"] =
      async (operation) => {
        lockSpy();
        return operation();
      };
    const { ops } = makeOps({
      reloadAuthority: vi.fn(async () => ({
        configuredChoices: { ...DEFAULT_PER_SURFACE },
        existingIntegrityState: oldState,
      })),
      withProvisioningLock,
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "manifest_rollback",
    });
    expect(lockSpy).toHaveBeenCalledOnce();
    expect(ops.commitVerified).not.toHaveBeenCalled();
    expect(ops.recordFailure).not.toHaveBeenCalled();
  });

  it("treats V1 input as rollback once an armed V2 floor exists", async () => {
    const oldState = {
      manifest_version_floor: 9,
      ollama_models_root: ROOT,
    } as LocalIntegrityStateV2;
    const { ops } = makeOps({
      reloadAuthority: vi.fn(async () => ({
        configuredChoices: { ...DEFAULT_PER_SURFACE },
        existingIntegrityState: oldState,
      })),
      verifyManifest: () => ({ ok: false, reason: "downgrade" }),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "manifest_rollback",
    });
    expect(ops.commitVerified).not.toHaveBeenCalled();
    expect(ops.recordFailure).not.toHaveBeenCalled();
  });

  it("keeps the persisted root authoritative after the environment resolver changes", async () => {
    const existingIntegrityState = {
      manifest_version_floor: 9,
      ollama_models_root: ROOT,
    } as LocalIntegrityStateV2;
    const resolveModelsRoot = vi.fn(async () => "/changed/by/environment");
    const runtimeVerifier = { verify: vi.fn(async () => runtimeSuccess()) };
    const { ops, commits } = makeOps({
      reloadAuthority: vi.fn(async () => ({
        configuredChoices: { ...DEFAULT_PER_SURFACE },
        existingIntegrityState,
      })),
      resolveModelsRoot,
      runtimeVerifier,
    });
    await runLocalIntelligenceProvisioning(ops);
    expect(resolveModelsRoot).not.toHaveBeenCalled();
    expect(runtimeVerifier.verify).toHaveBeenCalledWith(
      expect.objectContaining({ rootReal: ROOT }),
    );
    expect(commits[0]!.integrityState.ollama_models_root).toBe(ROOT);
  });

  it("a lock contender refuses before verify, pull, or authoritative mutation", async () => {
    const lockError = new CrossProcessLockError(
      "cross-process lock /fortress/_intelligence/.q5-provisioning.lock held; clear it manually",
    );
    const { ops } = makeOps({
      withProvisioningLock: vi.fn(async () => { throw lockError; }),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "integrity_io_unavailable",
    });
    expect(ops.runtimeVerifier.verify).not.toHaveBeenCalled();
    expect(ops.pull).not.toHaveBeenCalled();
    expect(ops.commitVerified).not.toHaveBeenCalled();
    expect(ops.recordFailure).not.toHaveBeenCalled();
    expect(ops.print).toHaveBeenCalledWith(lockError.message);
    expect(ops.audit).toHaveBeenCalledWith(expect.objectContaining({
      details: {
        reason: "integrity_io_unavailable",
        affected_surfaces: LOCAL_SURFACES,
      },
    }));
  });

  it("records an honest failure when an unexpected crash follows a successful pull", async () => {
    const runtimeVerifier = {
      verify: vi.fn()
        .mockResolvedValueOnce({
          ok: false,
          state: "tags_model_absent",
          reason: "runtime_model_absent",
          runtimeTag: "qwen2.5:1.5b",
        })
        .mockRejectedValueOnce(new Error("crash-after-pull")),
    };
    const { ops } = makeOps({ runtimeVerifier });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "integrity_io_unavailable",
    });
    expect(ops.pull).toHaveBeenCalledOnce();
    expect(ops.commitVerified).not.toHaveBeenCalled();
    expect(ops.recordFailure).toHaveBeenCalledOnce();
  });

  it("keeps production-null and non-TTY paths inert before root or registry inspection", async () => {
    const absent = makeOps({
      manifestText: null,
      verifyManifest: () => ({ ok: false, reason: "absent" }),
    });
    await expect(runLocalIntelligenceProvisioning(absent.ops)).resolves.toEqual({
      kind: "refused",
      reason: "integrity_state_absent",
    });
    expect(absent.ops.probeHardware).not.toHaveBeenCalled();
    expect(absent.ops.resolveModelsRoot).not.toHaveBeenCalled();

    const headless = makeOps({ isTty: false, preAnswered: true });
    await expect(runLocalIntelligenceProvisioning(headless.ops)).resolves.toEqual({
      kind: "refused",
      reason: "non_tty",
    });
    expect(headless.ops.probeHardware).not.toHaveBeenCalled();
  });

  it("renders V2 manifest semantics and never calls the root a weights hash", () => {
    expect(MODEL_REGISTRY_PROVIDER_CATEGORY).toBe("model-registry");
    expect(renderLocalProvisioningPlan({
      installRuntime: true,
      platform: "darwin",
      models: [MODEL],
    })).toEqual([
      "Local intelligence setup plan (no changes have been made):",
      "- Install Ollama using the platform adapter after confirmation.",
      "- Pull qwen2.5:1.5b from registry.ollama.ai (1.5B parameters; license Apache-2.0).",
      "- Verify its signed Ollama manifest root and required on-disk artifacts before binding.",
    ]);
  });
});
