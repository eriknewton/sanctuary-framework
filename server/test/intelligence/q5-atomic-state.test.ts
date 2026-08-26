import { ed25519 } from "@noble/curves/ed25519";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  computeModelManifestV2BodyDigest,
  type LocalIntegrityStateV2,
  type ModelManifestBodyV2,
  type ModelManifestModelV2,
  type SignedModelManifestV2,
  type VerifiedLocalBindingV2,
} from "../../src/intelligence/model-manifest-v2.js";
import { IMMUNE_MODEL_LOAD_SURFACES } from "../../src/intelligence/model-manifest-v2.js";
import {
  INTELLIGENCE_NAMESPACE,
  IntelligenceConfigStore,
  SUBSTRATE_CONFIG_KEY,
} from "../../src/intelligence/policy-store.js";
import { Q5_PROVISIONING_LOCK_FILE } from "../../src/intelligence/provisioning.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import { SURFACES, type SubstrateConfig, type Surface } from "../../src/intelligence/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { withCrossProcessLock } from "../../src/storage/cross-process-lock.js";
import { canonicalJson } from "../../src/v1/operator-signed.js";

const PRIVATE_KEY = new Uint8Array(32).fill(31);
const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY);
const ROOT = "/var/lib/ollama/models";
const HASH = "1".repeat(64);
const COMMITTED_AT = "2026-08-25T12:00:00.000Z";
const temporaryRoots: string[] = [];

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

function body(version = 9): ModelManifestBodyV2 {
  const defaults = Object.fromEntries(
    SURFACES.map((surface) => [
      surface,
      surface === "gate-explanation" ? null : MODEL.model_id,
    ]),
  ) as Record<Surface, string | null>;
  return {
    schema_version: 2,
    manifest_version: version,
    models: { [MODEL.model_id]: structuredClone(MODEL) },
    tiers: {
      baseline: [MODEL.model_id],
      mid: [MODEL.model_id],
      pro: [MODEL.model_id],
    },
    surface_defaults: {
      baseline: structuredClone(defaults),
      mid: structuredClone(defaults),
      pro: structuredClone(defaults),
    },
  };
}

function sign(manifestBody: ModelManifestBodyV2): SignedModelManifestV2 {
  const message = new TextEncoder().encode(
    `sanctuary.model-manifest.v2\n${canonicalJson(manifestBody)}`,
  );
  return {
    body: manifestBody,
    signature: toBase64url(ed25519.sign(message, PRIVATE_KEY)),
  };
}

function binding(surface: Surface, manifestVersion = 9): VerifiedLocalBindingV2 {
  return {
    model_id: MODEL.model_id,
    runtime_tag: "qwen2.5:1.5b",
    ollama_identity: structuredClone(MODEL.ollama_identity),
    assurance: IMMUNE_MODEL_LOAD_SURFACES.includes(
      surface as (typeof IMMUNE_MODEL_LOAD_SURFACES)[number],
    ) ? "immune" : "light",
    manifest_version: manifestVersion,
  };
}

function integrityState(manifestBody = body()): LocalIntegrityStateV2 {
  const bindings = Object.create(null) as Partial<Record<Surface, VerifiedLocalBindingV2>>;
  for (const surface of SURFACES) {
    if (surface !== "gate-explanation") {
      bindings[surface] = binding(surface, manifestBody.manifest_version);
    }
  }
  return {
    state: "armed",
    schema_version: 2,
    manifest_version_floor: manifestBody.manifest_version,
    signed_manifest: sign(manifestBody),
    signed_body_sha256: computeModelManifestV2BodyDigest(manifestBody),
    ollama_models_root: ROOT,
    bindings,
    committed_at: COMMITTED_AT,
  };
}

function runtimeTags(state: LocalIntegrityStateV2) {
  return Object.fromEntries(
    Object.entries(state.bindings).map(([surface, value]) => [surface, value!.runtime_tag]),
  ) as Partial<Record<Surface, string>>;
}

function selectorFixture(storage: StorageBackend = new MemoryStorage()) {
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "q5-state-test",
    modelManifestV2PublicKey: PUBLIC_KEY,
  });
  return { storage, masterKey, auditLog, selector };
}

async function writeConfigUnchecked(
  storage: StorageBackend,
  masterKey: Uint8Array,
  config: unknown,
): Promise<void> {
  // Must match HKDF_INFO in intelligence/policy-store.ts; this fixture writes
  // deliberately invalid encrypted records that the shipped loader must reject.
  const key = derivePurposeKey(masterKey, "intelligence-substrate-config");
  const encrypted = encrypt(stringToBytes(JSON.stringify(config)), key);
  await storage.write(
    INTELLIGENCE_NAMESPACE,
    SUBSTRATE_CONFIG_KEY,
    stringToBytes(JSON.stringify(encrypted)),
  );
}

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("Q5D persisted atomic state", () => {
  it("migrates legacy V1 to armed V2 in one save and revalidates on restart", async () => {
    const { selector, storage, masterKey, auditLog } = selectorFixture();
    await selector.load();
    expect(selector.getConfig().version).toBe(1);
    const state = integrityState();
    await selector.commitLocalIntegrityProvisioning(state, runtimeTags(state));
    expect(selector.getConfig()).toMatchObject({
      version: 2,
      customLocalModelTags: { concierge: "qwen2.5:1.5b" },
      localIntegrityState: {
        manifest_version_floor: 9,
        signed_manifest: state.signed_manifest,
        ollama_models_root: ROOT,
      },
    });

    const restarted = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "q5-state-test",
      modelManifestV2PublicKey: PUBLIC_KEY,
    });
    await restarted.load();
    expect(restarted.getConfig().version).toBe(2);
    expect(restarted.getConfig().localIntegrityState?.bindings["sentinel-scoring"])
      .toEqual(binding("sentinel-scoring"));
  });

  it("save failure preserves the old in-memory and durable config", async () => {
    const base = new MemoryStorage();
    let failWrites = false;
    const storage: StorageBackend = {
      write: async (...args) => {
        if (failWrites) throw new Error("injected pre-write crash");
        return base.write(...args);
      },
      read: (...args) => base.read(...args),
      delete: (...args) => base.delete(...args),
      list: (...args) => base.list(...args),
      exists: (...args) => base.exists(...args),
      totalSize: () => base.totalSize(),
      listNamespaces: () => base.listNamespaces(),
    };
    const fixture = selectorFixture(storage);
    await fixture.selector.load();
    failWrites = true;
    const state = integrityState();
    await expect(
      fixture.selector.commitLocalIntegrityProvisioning(state, runtimeTags(state)),
    ).rejects.toThrow("injected pre-write crash");
    expect(fixture.selector.getConfig().version).toBe(1);
    failWrites = false;
    expect((await new IntelligenceConfigStore(
      storage,
      fixture.masterKey,
      { modelManifestV2PublicKey: PUBLIC_KEY },
    ).load()).config.version).toBe(1);
  });

  it("crash after atomic storage replacement exposes the new complete record, never mixed fields", async () => {
    const base = new MemoryStorage();
    let throwAfterWrite = false;
    const storage: StorageBackend = {
      write: async (...args) => {
        await base.write(...args);
        if (throwAfterWrite) throw new Error("injected post-replacement crash");
      },
      read: (...args) => base.read(...args),
      delete: (...args) => base.delete(...args),
      list: (...args) => base.list(...args),
      exists: (...args) => base.exists(...args),
      totalSize: () => base.totalSize(),
      listNamespaces: () => base.listNamespaces(),
    };
    const fixture = selectorFixture(storage);
    await fixture.selector.load();
    throwAfterWrite = true;
    const state = integrityState();
    await expect(
      fixture.selector.commitLocalIntegrityProvisioning(state, runtimeTags(state)),
    ).rejects.toThrow("post-replacement crash");
    expect(fixture.selector.getConfig().version).toBe(1);
    throwAfterWrite = false;
    const loaded = await new IntelligenceConfigStore(
      storage,
      fixture.masterKey,
      { modelManifestV2PublicKey: PUBLIC_KEY },
    ).load();
    expect(loaded.kind).toBe("loaded");
    expect(loaded.config).toMatchObject({
      version: 2,
      customLocalModelTags: { concierge: "qwen2.5:1.5b" },
      localIntegrityState: { manifest_version_floor: 9 },
    });
  });

  it.each([
    ["missing complete record", (config: Record<string, unknown>) => {
      delete config.localIntegrityState;
    }],
    ["stripped binding", (config: Record<string, unknown>) => {
      delete ((config.localIntegrityState as LocalIntegrityStateV2).bindings.concierge);
    }],
    ["tampered signed envelope", (config: Record<string, unknown>) => {
      (config.localIntegrityState as LocalIntegrityStateV2).signed_manifest.signature =
        "A".repeat(86);
    }],
    ["changed runtime tag", (config: Record<string, unknown>) => {
      (config.customLocalModelTags as Record<string, string>).concierge = "other:tag";
    }],
    ["changed model", (config: Record<string, unknown>) => {
      (config.localIntegrityState as LocalIntegrityStateV2).bindings.concierge!.model_id =
        "other-model";
    }],
    ["changed root", (config: Record<string, unknown>) => {
      (config.localIntegrityState as LocalIntegrityStateV2).ollama_models_root = "relative";
    }],
  ])("rejects an armed V2 with %s rather than reading it as legacy", async (_label, mutate) => {
    const { selector, storage, masterKey } = selectorFixture();
    await selector.load();
    const state = integrityState();
    await selector.commitLocalIntegrityProvisioning(state, runtimeTags(state));
    const valid = structuredClone(selector.getConfig()) as unknown as Record<string, unknown>;
    mutate(valid);
    await writeConfigUnchecked(storage, masterKey, valid);
    const store = new IntelligenceConfigStore(
      storage,
      masterKey,
      { modelManifestV2PublicKey: PUBLIC_KEY },
    );
    const outcome = await store.load();
    expect(outcome.kind).toBe("integrity-state-invalid");
  });

  it("rederives surface/model authority from the newly verified envelope", async () => {
    const { selector, storage, masterKey } = selectorFixture();
    await selector.load();
    const state = integrityState();
    await selector.commitLocalIntegrityProvisioning(state, runtimeTags(state));
    const changedBody = body();
    for (const tier of ["baseline", "mid", "pro"] as const) {
      changedBody.surface_defaults[tier].concierge = null;
    }
    const changed = structuredClone(selector.getConfig()) as Extract<SubstrateConfig, { version: 2 }>;
    changed.localIntegrityState.signed_manifest = sign(changedBody);
    changed.localIntegrityState.signed_body_sha256 =
      computeModelManifestV2BodyDigest(changedBody);
    await writeConfigUnchecked(storage, masterKey, changed);
    const outcome = await new IntelligenceConfigStore(
      storage,
      masterKey,
      { modelManifestV2PublicKey: PUBLIC_KEY },
    ).load();
    expect(outcome).toMatchObject({
      kind: "integrity-state-invalid",
      reason: "binding_mismatch",
    });
  });

  it("refuses config clear and reset from manufacturing an armed-to-unarmed transition", async () => {
    const { selector, storage, masterKey } = selectorFixture();
    await selector.load();
    const state = integrityState();
    await selector.commitLocalIntegrityProvisioning(state, runtimeTags(state));
    const store = new IntelligenceConfigStore(
      storage,
      masterKey,
      { modelManifestV2PublicKey: PUBLIC_KEY },
    );
    await expect(store.clear()).rejects.toThrow(/Q5 integrity state refused/);
    await expect(selector.resetToDefaults()).resolves.toBeUndefined();
    expect(selector.getConfig().version).toBe(2);
    expect(selector.getConfig().localIntegrityState).toEqual(state);
  });

  it("refuses a stale routine selector write from replacing durable armed V2 with V1", async () => {
    const { storage, masterKey, auditLog, selector: staleWriter } = selectorFixture();
    await staleWriter.load();
    expect(staleWriter.getConfig().version).toBe(1);

    const armingWriter = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "q5-arming-writer",
      modelManifestV2PublicKey: PUBLIC_KEY,
    });
    await armingWriter.load();
    const state = integrityState(body(9));
    await armingWriter.commitLocalIntegrityProvisioning(state, runtimeTags(state));

    await expect(staleWriter.setFallbackBehavior(
      "concierge",
      "disable-surface",
    )).rejects.toMatchObject({ reason: "integrity_state_invalid" });
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

  it("uses the durable V2 floor at save even when a provisioning selector holds stale V1", async () => {
    const { storage, masterKey, auditLog, selector: staleProvisioner } = selectorFixture();
    await staleProvisioner.load();
    const newerProvisioner = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "q5-newer-provisioner",
      modelManifestV2PublicKey: PUBLIC_KEY,
    });
    await newerProvisioner.load();
    const floorNine = integrityState(body(9));
    await newerProvisioner.commitLocalIntegrityProvisioning(
      floorNine,
      runtimeTags(floorNine),
    );

    const staleFloorEight = integrityState(body(8));
    await expect(staleProvisioner.commitLocalIntegrityProvisioning(
      staleFloorEight,
      runtimeTags(staleFloorEight),
    )).rejects.toMatchObject({ reason: "manifest_rollback" });
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

describe("Q5D dedicated provisioning lock", () => {
  it("deterministically refuses a contender while the O_EXCL holder remains live", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-q5d-lock-"));
    temporaryRoots.push(root);
    const storage = new FilesystemStorage(root);
    let releaseHolder!: () => void;
    const holderGate = new Promise<void>((resolve) => { releaseHolder = resolve; });
    let holderAcquired!: () => void;
    const acquired = new Promise<void>((resolve) => { holderAcquired = resolve; });
    const holder = withCrossProcessLock(
      storage,
      INTELLIGENCE_NAMESPACE,
      Q5_PROVISIONING_LOCK_FILE,
      async () => {
        holderAcquired();
        await holderGate;
      },
    );
    await acquired;
    let observedContention!: () => void;
    const contended = new Promise<void>((resolve) => { observedContention = resolve; });
    const contenderOperation = vi.fn(async () => undefined);
    const contender = withCrossProcessLock(
      storage,
      INTELLIGENCE_NAMESPACE,
      Q5_PROVISIONING_LOCK_FILE,
      contenderOperation,
      {
        timeoutMs: 20,
        retryMs: 1,
        onContended: (attempt) => {
          if (attempt === 1) observedContention();
        },
      },
    );
    await contended;
    await expect(contender).rejects.toThrow(/refusing to proceed concurrently/);
    expect(contenderOperation).not.toHaveBeenCalled();
    releaseHolder();
    await holder;
  });
});
