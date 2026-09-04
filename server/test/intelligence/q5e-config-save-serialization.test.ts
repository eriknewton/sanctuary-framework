// fail-before-exempt: Q5E residual 1 adds a two-saver adversarial schedule that pins the config-save lock already on main; the divergence was planted by bypassing the lock in the source and the test failed there (evidence recorded in the PR), so this file passes against the unmodified base by design.

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { buildDefaultConfig } from "../../src/intelligence/defaults.js";
import {
  IntelligenceConfigStore,
  LocalIntegrityStateLoadError,
} from "../../src/intelligence/policy-store.js";
import type { SubstrateConfig } from "../../src/intelligence/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type {
  FilesystemStorageCapabilities,
  StorageBackend,
} from "../../src/storage/interface.js";
import { runLocalIntelligenceSetup } from "../../src/wrap/local-intelligence.js";
import {
  Q5E_PUBLIC_KEY,
  q5eBody,
  q5eIntegrityState,
  q5eRuntimeTags,
  signQ5eBody,
} from "./q5e-fixtures.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) =>
    rm(root, { recursive: true, force: true })));
});

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

describe("Q5E config-save serialization", () => {
  it("prevents a routine stale V1 save from replacing a concurrently committed armed V2 record", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-q5e-save-lock-"));
    roots.push(root);
    const storage = new FilesystemStorage(root);
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const initialStore = new IntelligenceConfigStore(storage, masterKey, {
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    });
    const initial = await initialStore.save(buildDefaultConfig());
    const staleRoutineNext = { ...initial, applyToAllSurfaces: false };

    const verificationEntered = deferred();
    const releaseVerification = deferred();
    const releaseRoutineRead = deferred();
    let routineReadCount = 0;
    let provisioningCommitted = false;
    const routineStorage: StorageBackend & FilesystemStorageCapabilities = {
      namespacePath: (namespace) => storage.namespacePath(namespace),
      writeDurable: (...args) => storage.writeDurable(...args),
      write: (...args) => storage.write(...args),
      read: async (...args) => {
        const captured = await storage.read(...args);
        routineReadCount += 1;
        await releaseRoutineRead.promise;
        return captured;
      },
      delete: (...args) => storage.delete(...args),
      list: (...args) => storage.list(...args),
      exists: (...args) => storage.exists(...args),
      totalSize: () => storage.totalSize(),
      listNamespaces: () => storage.listNamespaces(),
    };
    const routineStore = new IntelligenceConfigStore(routineStorage, masterKey, {
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    });

    const manifestText = JSON.stringify(signQ5eBody(q5eBody()));
    const setup = runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "q5e-save-provisioner",
      isTty: true,
      print: vi.fn(),
    }, {
      loadManifest: async () => manifestText,
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
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
        verify: async (request) => {
          verificationEntered.resolve();
          await releaseVerification.promise;
          return {
            ok: true,
            state: "runtime_manifest_match",
            runtimeTag: request.binding.runtime_tag,
            observedManifestDigest:
              request.binding.ollama_identity.ollama_manifest_sha256,
          };
        },
      },
      immuneVerifier: {
        verify: async (request) => ({
          ok: true,
          state: "immune_verified",
          runtimeTag: request.binding.runtime_tag,
          expectedManifestDigest:
            request.binding.ollama_identity.ollama_manifest_sha256,
          descriptorCount: 2,
          bytesHashed: 128,
          verifiedArtifactDigests: ["3".repeat(64)],
          completedAtMonotonicMs: 1,
          cached: false,
        }),
      },
      confirm: vi.fn(),
    });
    await verificationEntered.promise;

    const routineSave = routineStore.save(staleRoutineNext).then(
      () => "saved" as const,
      () => "refused" as const,
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    await new Promise<void>((resolve) => setImmediate(resolve));
    const routineReadBeforeProvisionCommit = routineReadCount > 0;

    releaseVerification.resolve();
    await expect(setup).resolves.toMatchObject({ kind: "already-provisioned" });
    provisioningCommitted = true;
    releaseRoutineRead.resolve();
    const routineOutcome = await routineSave;

    const durable = await initialStore.load();
    expect(routineReadBeforeProvisionCommit).toBe(false);
    expect(provisioningCommitted).toBe(true);
    expect(routineOutcome).toBe("refused");
    expect(durable).toMatchObject({
      kind: "loaded",
      config: {
        version: 2,
        localIntegrityState: { state: "armed" },
      },
    });
  });

  it("keeps a concurrent stale V1 save out of an armed V2 save's check/write window and refuses it afterward", async () => {
    // Adversarial schedule (AGENTS rule 12): two non-provisioning savers race
    // at the check-then-write boundary. The armed saver is frozen after its
    // durable check and before its write; the stale V1 saver starts while it
    // is frozen. Without serialization the stale check would read the old V1
    // record, pass, and land V1 over the committed V2 once released.
    const root = await mkdtemp(join(tmpdir(), "sanctuary-q5e-two-savers-"));
    roots.push(root);
    const storage = new FilesystemStorage(root);
    const masterKey = generateRandomKey();
    const baseline = new IntelligenceConfigStore(storage, masterKey, {
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    });
    const initial = await baseline.save(buildDefaultConfig());
    const state = q5eIntegrityState("/var/lib/ollama/models");
    const armedNext: SubstrateConfig = {
      ...initial,
      version: 2,
      customLocalModelTags: q5eRuntimeTags(state),
      localIntegrityState: state,
    };
    const staleV1Next: SubstrateConfig = { ...initial, applyToAllSurfaces: false };

    const delegate = (): StorageBackend & FilesystemStorageCapabilities => ({
      namespacePath: (namespace) => storage.namespacePath(namespace),
      writeDurable: (...args) => storage.writeDurable(...args),
      write: (...args) => storage.write(...args),
      read: (...args) => storage.read(...args),
      delete: (...args) => storage.delete(...args),
      list: (...args) => storage.list(...args),
      exists: (...args) => storage.exists(...args),
      totalSize: () => storage.totalSize(),
      listNamespaces: () => storage.listNamespaces(),
    });

    const armedWriteEntered = deferred();
    const releaseArmedWrite = deferred();
    const armedStorage = delegate();
    armedStorage.writeDurable = async (...args) => {
      armedWriteEntered.resolve();
      await releaseArmedWrite.promise;
      return storage.writeDurable(...args);
    };
    const armedStore = new IntelligenceConfigStore(armedStorage, masterKey, {
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    });

    let staleReadCount = 0;
    let staleContentions = 0;
    const staleStorage = delegate();
    staleStorage.read = async (...args) => {
      staleReadCount += 1;
      return storage.read(...args);
    };
    const staleStore = new IntelligenceConfigStore(staleStorage, masterKey, {
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
      saveLockOptions: {
        retryMs: 10,
        onContended: () => {
          staleContentions += 1;
        },
      },
    });

    const armedSave = armedStore.save(armedNext);
    await armedWriteEntered.promise;
    const staleSave = staleStore.save(staleV1Next).then(
      () => "saved" as const,
      (error: unknown) => error,
    );
    // Wait for the stale saver to OBSERVE the held lock (not merely for time
    // to pass), then confirm its durable check has still not run.
    await vi.waitFor(() => {
      expect(staleContentions).toBeGreaterThan(0);
    });
    const staleReadWhileArmedHeld = staleReadCount;

    releaseArmedWrite.resolve();
    await expect(armedSave).resolves.toMatchObject({ version: 2 });
    const staleOutcome = await staleSave;

    expect(staleReadWhileArmedHeld).toBe(0);
    expect(staleReadCount).toBe(1);
    expect(staleOutcome).toBeInstanceOf(LocalIntegrityStateLoadError);
    expect((staleOutcome as LocalIntegrityStateLoadError).reason).toBe(
      "integrity_state_invalid",
    );
    const durable = await baseline.load();
    expect(durable).toMatchObject({
      kind: "loaded",
      config: {
        version: 2,
        localIntegrityState: { state: "armed", manifest_version_floor: 17 },
      },
    });
  });
});
