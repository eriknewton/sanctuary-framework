import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { buildDefaultConfig } from "../../src/intelligence/defaults.js";
import { IntelligenceConfigStore } from "../../src/intelligence/policy-store.js";
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
});
