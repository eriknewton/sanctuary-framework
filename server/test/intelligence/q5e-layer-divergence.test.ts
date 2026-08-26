import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import {
  createCadencedImmuneDiskVerifier,
  createNodeImmuneFileSystemAdapter,
  createOnDiskImmuneVerifier,
} from "../../src/intelligence/immune-disk-verifier.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { OllamaRuntimeEvidenceClient } from "../../src/intelligence/runtime-light-verifier.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  Q5E_PUBLIC_KEY,
  Q5E_RUNTIME_TAG,
  q5eBody,
  q5eIntegrityState,
  q5eRuntimeTags,
  sha256Hex,
} from "./q5e-fixtures.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) =>
    rm(root, { recursive: true, force: true })));
});

describe("Q5E planted on-disk layer divergence", () => {
  it("shows runtime-only light evidence misses unchanged-name mutation while immune activation refuses it", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "sanctuary-q5e-layer-")));
    roots.push(root);
    const configBytes = new TextEncoder().encode("config-bytes");
    const originalLayerBytes = new TextEncoder().encode("trusted-layer");
    const mutatedLayerBytes = new TextEncoder().encode("mutated-layer");
    expect(mutatedLayerBytes.byteLength).toBe(originalLayerBytes.byteLength);
    const configDigest = sha256Hex(configBytes);
    const layerDigest = sha256Hex(originalLayerBytes);
    const manifestBytes = new TextEncoder().encode(JSON.stringify({
      schemaVersion: 2,
      config: {
        mediaType: "application/vnd.ollama.image.config",
        digest: `sha256:${configDigest}`,
        size: configBytes.byteLength,
      },
      layers: [{
        mediaType: "application/vnd.ollama.image.model",
        digest: `sha256:${layerDigest}`,
        size: originalLayerBytes.byteLength,
      }],
    }));
    const manifestDigest = sha256Hex(manifestBytes);
    const manifestDir = join(
      root,
      "manifests",
      "registry.ollama.ai",
      "library",
      "qwen2.5",
    );
    const blobsDir = join(root, "blobs");
    await mkdir(manifestDir, { recursive: true });
    await mkdir(blobsDir, { recursive: true });
    await writeFile(join(manifestDir, "1.5b"), manifestBytes);
    await writeFile(join(blobsDir, `sha256-${configDigest}`), configBytes);
    // Plant the divergence under the unchanged authenticated digest filename.
    await writeFile(join(blobsDir, `sha256-${layerDigest}`), mutatedLayerBytes);

    let generateCalls = 0;
    const fetchImpl = vi.fn(async (input: Parameters<typeof fetch>[0]) => {
      const url = input instanceof Request
        ? input.url
        : typeof input === "string" ? input : input.toString();
      const pathname = new URL(url).pathname;
      if (pathname === "/api/show") {
        return new Response(JSON.stringify({ model_info: {} }), { status: 200 });
      }
      if (pathname === "/api/tags") {
        return new Response(JSON.stringify({
          models: [{ name: Q5E_RUNTIME_TAG, digest: manifestDigest }],
        }), { status: 200 });
      }
      if (pathname === "/api/generate") {
        generateCalls += 1;
        return new Response(JSON.stringify({ response: "must not run" }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    }) as typeof fetch;

    const body = q5eBody(manifestDigest);
    const state = q5eIntegrityState(root, body);
    const immuneBinding = state.bindings["sentinel-scoring"]!;
    const runtimeOnly = new OllamaRuntimeEvidenceClient({ fetchImpl, endpoint: "http://localhost:11434" });
    await expect(runtimeOnly.verify({ rootReal: root, binding: immuneBinding }))
      .resolves.toMatchObject({ ok: true, observedManifestDigest: manifestDigest });

    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const provisioner = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "q5e-layer-provisioner",
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    });
    await provisioner.load();
    await provisioner.commitLocalIntegrityProvisioning(state, q5eRuntimeTags(state));

    const activated = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "q5e-layer-activated",
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
      runtimeIntegrityVerifier: runtimeOnly,
      immuneIntegrityVerifier: createCadencedImmuneDiskVerifier(
        createOnDiskImmuneVerifier({ fs: createNodeImmuneFileSystemAdapter() }),
      ),
      fetchImpl,
    });
    const handle = await activated.getSubstrate("sentinel-scoring");
    const response = await activated.invokeClassify("sentinel-scoring", {
      kind: "classify",
      items: ["dangerous tool"],
      categories: ["deny"],
    });
    expect(generateCalls).toBe(0);
    expect(handle.capability.classify).toBe(false);
    expect(response.failureClass).not.toBeNull();
    const events = await auditLog.query({ operation_type: INTEL_OPS.LOAD_INTEGRITY });
    expect(events.entries.at(-1)?.details).toMatchObject({
      reason: "layer_digest_mismatch",
      generation_refused: true,
    });
  });
});
