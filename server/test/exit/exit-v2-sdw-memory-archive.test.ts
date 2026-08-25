import { ed25519 } from "@noble/curves/ed25519";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  EXIT_BUNDLE_ARTIFACT_KINDS,
  EXIT_BUNDLE_MANIFEST_VERSION,
} from "../../src/contracts/v1.1/constants.js";
import {
  EXIT_V2_MANIFEST_VERSION,
  SDW_MEMORY_ARCHIVE_ARTIFACT_KIND,
  type ExitV2SdwMemoryArtifact,
  type ExitV2SdwMemoryLogicalPayload,
  type ExitV2SdwMemoryManifest,
} from "../../src/contracts/v1.2/exit-bundle-manifest.js";
import { decrypt, encrypt } from "../../src/core/encryption.js";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import {
  generateKeypair,
  legacyPublicKeyToDid,
  publicKeyToDid,
} from "../../src/core/identity.js";
import {
  exportExitV2SdwMemoryArchive,
  importExitV2SdwMemoryArchive,
  planExitV2SdwMemoryAdmission,
  participantExitSdwMemoryRetention,
  verifyExitV2SdwMemoryArchive,
  type ExitV2MemorySigner,
} from "../../src/exit/v2-memory-archive.js";
import { verifyExitBundle } from "../../src/exit/verifier.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { ingestClaudeCodeMemoryDirectory } from "../../src/sdw/adapters/claude-code-file-adapter.js";
import type {
  MemoryBackendAdapter,
  MemoryPassageInput,
} from "../../src/sdw/adapters/memory-backend.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { TestSdwMemoryBackendAdapter } from "../sdw/test-memory-backend.js";
import {
  restoreMemoryTranscodeArchive,
  transcodeMemoryDirectory,
} from "../../src/sdw/memory-transcode.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { KnownSignersStore } from "../../src/reputation/known-signers-store.js";
import { testMemoryProvenanceDependencies } from "../sdw/test-memory-backend.js";
import type { MemoryProvenanceSigningHandle } from "../../src/sdw/memory-provenance-contract.js";

const CLAUDE_FIXTURE = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/basic/", import.meta.url),
);
const NOW = "2026-08-15T06:30:00.000Z";
const cleanupTasks: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanupTasks.length > 0) await cleanupTasks.pop()!();
});

async function tempDir(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), `${prefix}-`));
  cleanupTasks.push(() => rm(path, { recursive: true, force: true }));
  return realpath(path);
}

async function makeAdapter(input: {
  readonly prefix: string;
  readonly ownerRef: string;
  readonly masterByte: number;
  readonly fortressId: string;
  readonly storageRoot?: string;
  readonly integrityState?: "state_PRE_MIGRATION" | "state_COMPLETE";
}): Promise<SdwMemoryBackendAdapter> {
  const root = input.storageRoot ?? await tempDir(input.prefix);
  return new TestSdwMemoryBackendAdapter({
    storage: new FilesystemStorage(root),
    masterKey: new Uint8Array(32).fill(input.masterByte),
    fortressId: input.fortressId,
    ownerRef: input.ownerRef,
    now: () => NOW,
    resolveMemoryIntegrityState: async () => input.integrityState ?? "state_PRE_MIGRATION",
  });
}

function makeSigner(fortressId: string): ExitV2MemorySigner {
  const { publicKey, privateKey } = generateKeypair();
  return {
    identity_id: `identity-${fortressId}`,
    fortress_id: fortressId,
    public_key: toBase64url(publicKey),
    did: publicKeyToDid(publicKey),
    sign: (bytes) => ed25519.sign(bytes, privateKey),
  };
}

function signingFixture(seedByte: number, fortressId: string): {
  signer: ExitV2MemorySigner;
  handle: MemoryProvenanceSigningHandle;
} {
  const privateKey = new Uint8Array(32).fill(seedByte);
  const publicKey = ed25519.getPublicKey(privateKey);
  const did = publicKeyToDid(publicKey);
  const identityId = `identity-${fortressId}`;
  return {
    signer: { identity_id: identityId, fortress_id: fortressId,
      public_key: toBase64url(publicKey), did,
      sign: (bytes) => ed25519.sign(bytes, privateKey) },
    handle: { identity_id: identityId, did, public_key: publicKey,
      sign: (bytes) => ed25519.sign(bytes, privateKey) },
  };
}

async function makeSourceArchive(ownerRef = "owner-a", integrityState: "state_PRE_MIGRATION" | "state_COMPLETE" = "state_PRE_MIGRATION"): Promise<{
  readonly adapter: SdwMemoryBackendAdapter;
  readonly archiveId: string;
}> {
  const adapter = await makeAdapter({
    prefix: `exit-v2-source-${ownerRef}`,
    ownerRef,
    masterByte: ownerRef === "owner-a" ? 41 : 42,
    fortressId: "fortress-source",
    integrityState,
  });
  await ingestClaudeCodeMemoryDirectory(adapter, CLAUDE_FIXTURE, { ingestedAt: NOW });
  const outputParent = await tempDir(`exit-v2-source-projection-${ownerRef}`);
  const result = await transcodeMemoryDirectory(
    adapter,
    "claude-code",
    "codex",
    join(outputParent, "projection"),
    { now: () => NOW },
  );
  return { adapter, archiveId: result.archive_id };
}

async function exportArchive(
  source: Awaited<ReturnType<typeof makeSourceArchive>>,
  signer = makeSigner("fortress-source"),
) {
  return exportExitV2SdwMemoryArchive({
    adapter: source.adapter,
    archiveId: source.archiveId,
    sourceFortressId: "fortress-source",
    exportApprovalAuditId: "audit-approved-123",
    sourceSanctuaryVersion: "1.7.2",
    signer,
    now: () => NOW,
  });
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function synchronizeInitialPassageReads(
  destination: SdwMemoryBackendAdapter,
): MemoryBackendAdapter {
  let initialReads = 0;
  let releaseInitialReads: () => void = () => {};
  const bothInitialReads = new Promise<void>((resolve) => {
    releaseInitialReads = resolve;
  });
  return new Proxy(destination, {
    get(target, property, receiver): unknown {
      if (property === "getPassage") {
        return async (passageId: string) => {
          const observed = await target.getPassage(passageId);
          if (initialReads < 2) {
            initialReads++;
            if (initialReads === 2) releaseInitialReads();
            await bothInitialReads;
          }
          return observed;
        };
      }
      const value = Reflect.get(target, property, receiver) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

describe("Exit V2 SDW memory archive", () => {
  it("adds a distinct V2 contract while leaving the closed V1 contract byte-stable", async () => {
    expect(EXIT_BUNDLE_MANIFEST_VERSION).toBe("SANCTUARY_EXIT_BUNDLE_V1");
    expect(EXIT_BUNDLE_ARTIFACT_KINDS).toEqual([
      "public_identity",
      "encrypted_state",
      "policy_set",
      "audit_receipts",
      "reputation_bundle",
      "commitments",
      "placeholder_vault_metadata",
    ]);
    expect(EXIT_V2_MANIFEST_VERSION).toBe("SANCTUARY_EXIT_BUNDLE_V2");
    expect(SDW_MEMORY_ARCHIVE_ARTIFACT_KIND).toBe("sdw_memory_archive");

    const dir = await tempDir("exit-v1-rejects-v2");
    await writeFile(join(dir, "manifest.json"), JSON.stringify({
      body: { manifest_version: EXIT_V2_MANIFEST_VERSION },
      signature: "invalid",
    }), { mode: 0o600 });
    const result = await verifyExitBundle(dir);
    expect(result).toMatchObject({ passed: false, failure_class: "manifest_unknown_version" });
  });

  it("exports only ciphertext/public bindings under a fresh 32-byte transfer key", async () => {
    const source = await makeSourceArchive("owner-a", "state_COMPLETE");
    const sourceCount = await source.adapter.countPassages();
    const first = await exportArchive(source);
    const second = await exportArchive(source);
    expect(await source.adapter.countPassages()).toBe(sourceCount);

    expect(first.manifest.body.manifest_version).toBe(EXIT_V2_MANIFEST_VERSION);
    expect(first.manifest.body.artifacts).toHaveLength(1);
    expect(first.manifest.body.artifacts[0]?.kind).toBe(SDW_MEMORY_ARCHIVE_ARTIFACT_KIND);
    expect(first.transfer_key).toHaveLength(32);
    expect(second.transfer_key).toHaveLength(32);
    expect(Buffer.from(first.transfer_key).equals(Buffer.from(second.transfer_key))).toBe(false);

    const publicBytes = Buffer.from(first.artifact_bytes).toString("utf8");
    expect(publicBytes).not.toContain("Prefer brief status notes with concrete next steps");
    expect(publicBytes).not.toContain("MEMORY.md");
    expect(publicBytes).not.toContain(source.adapter.ownerRef);
    expect(publicBytes).not.toContain(source.archiveId);
    expect(publicBytes).not.toContain(Buffer.from(first.transfer_key).toString("hex"));

    const key = first.transfer_key.slice();
    await expect(verifyExitV2SdwMemoryArchive({
      manifest: first.manifest,
      artifactBytes: first.artifact_bytes,
      transferKey: key,
    })).resolves.toMatchObject({
      passed: true,
      source_lineage_ref: first.source_lineage_ref,
      source_file_count: 3,
    });
    expect(key).toEqual(new Uint8Array(32));
  });

  it("imports as destination-local ids with signed lineage in the same atomic batch", async () => {
    const source = await makeSourceArchive();
    const exported = await exportArchive(source);
    const destination = await makeAdapter({
      prefix: "exit-v2-destination",
      ownerRef: "owner-a",
      masterByte: 77,
      fortressId: "fortress-destination",
    });
    const destinationSigner = makeSigner("fortress-destination");
    let capturedInputs: readonly MemoryPassageInput[] = [];
    let putCalls = 0;
    const observingAdapter: MemoryBackendAdapter = new Proxy(destination, {
      get(target, property, receiver): unknown {
        if (property === "putPassagesIfAbsent") {
          return async (inputs: readonly MemoryPassageInput[], taint: "user_content") => {
            putCalls++;
            capturedInputs = inputs;
            return target.putPassagesIfAbsent(inputs, taint);
          };
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const key = exported.transfer_key.slice();

    const receipt = await importExitV2SdwMemoryArchive({
      adapter: observingAdapter,
      manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: key,
      signer: destinationSigner,
      now: () => NOW,
    });

    expect(key).toEqual(new Uint8Array(32));
    expect(receipt.destination_archive_id).not.toBe(source.archiveId);
    expect(receipt.source_lineage_ref).toBe(exported.source_lineage_ref);
    expect(receipt.lineage_signature).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(putCalls).toBe(1);
    expect(capturedInputs).toHaveLength(5); // three files + completed manifest + signed lineage
    expect(capturedInputs.some((input) => input.tags?.includes("memory_transcode_lineage"))).toBe(true);
    for (const input of capturedInputs) {
      const provenance = await destination.getPassageProvenance(input.passage_id!);
      expect(provenance.status).toBe("verified");
      if (provenance.status !== "verified") throw new Error("expected verified V1 import provenance");
      expect(provenance.companion.origin.body).toMatchObject({
        author_agent_id: "unknown_legacy",
        ingress_channel: "legacy_unknown",
        source_class: "legacy_unattested",
      });
      expect(provenance.companion.admission.body).toMatchObject({
        admission_channel: "exit_v2_import",
        origin_trust_tier: "legacy_unattested",
        verification_basis: "exit_v2_legacy_v1",
      });
      expect(provenance.companion.admission.body.origin_trust_tier).not.toBe("local_attested");
    }

    const restoredParent = await tempDir("exit-v2-restored");
    const restoredDir = join(restoredParent, "source");
    await restoreMemoryTranscodeArchive(destination, receipt.destination_archive_id, restoredDir);
    for (const path of ["MEMORY.md", "concise-updates.md", "rung-one-scope.md"]) {
      expect(await readFile(join(restoredDir, path))).toEqual(await readFile(join(CLAUDE_FIXTURE, path)));
    }
  });

  it("carries signed origins through a relayed second hop without laundering them as local", async () => {
    const source = await makeSourceArchive("owner-a", "state_COMPLETE");
    const sourceSigner = makeSigner("fortress-source");
    const sourceDeps = testMemoryProvenanceDependencies(new Uint8Array(32).fill(41));
    const firstExport = await exportExitV2SdwMemoryArchive({
      adapter: source.adapter, archiveId: source.archiveId,
      sourceFortressId: "fortress-source", exportApprovalAuditId: "audit-v2",
      sourceSanctuaryVersion: "1.7.2", signer: sourceSigner, formatVersion: 2,
      resolveProvenanceSigner: sourceDeps.resolveSignerPublicKey, now: () => NOW,
    });
    const destinationRoot = await tempDir("exit-v2-provenance-destination");
    const destinationMaster = new Uint8Array(32).fill(77);
    const destinationDeps = testMemoryProvenanceDependencies(destinationMaster);
    const importedSignerKeys = new Map<string, Uint8Array>();
    const destination = new SdwMemoryBackendAdapter({
      storage: new FilesystemStorage(destinationRoot), masterKey: destinationMaster,
      ownerRef: "owner-a", fortressId: "fortress-destination", now: () => NOW,
      resolvePrimarySigningHandle: destinationDeps.resolvePrimarySigningHandle,
      resolveSignerPublicKey: (identityId, did) =>
        destinationDeps.resolveSignerPublicKey(identityId, did) ?? importedSignerKeys.get(did),
      resolveMemoryIntegrityState: async () => "state_COMPLETE",
    });
    const destinationSigner = makeSigner("fortress-destination");
    const signerStore = new KnownSignersStore(
      new FilesystemStorage(destinationRoot), destinationMaster,
      { partition: "memory_provenance" },
    );
    const receipt = await importExitV2SdwMemoryArchive({
      adapter: destination, signer: destinationSigner,
      knownSignersStore: signerStore, manifest: firstExport.manifest,
      artifactBytes: firstExport.artifact_bytes,
      transferKey: firstExport.transfer_key.slice(), now: () => NOW,
      onProvenanceSignerPersisted: (did, publicKey) => importedSignerKeys.set(did, publicKey),
    });
    const imported = await destination.listPassages({});
    const importedFiles = imported.filter((passage) =>
      passage.tags.includes("memory_transcode_file"));
    expect(importedFiles).toHaveLength(3);
    for (const passage of importedFiles) {
      const provenance = await destination.getPassageProvenance(passage.passage_id);
      expect(provenance.status).toBe("verified");
      if (provenance.status !== "verified") continue;
      expect(provenance.companion.origin.body.origin_fortress_id).toBe("fortress-source");
      expect(provenance.companion.origin.body.signer_did).toBe(sourceDeps.handle.did);
      expect(provenance.companion.admission.body.origin_trust_tier).toBe("foreign_relayed");
      expect(provenance.companion.admission.body.destination_fortress_id)
        .toBe("fortress-destination");
    }
    expect(receipt.replayed).toBe(false);
    expect(await signerStore.lookup(sourceDeps.handle.did)).not.toBeNull();
  });

  it("keeps a direct origin byte-stable across restart and classifies the second hop as relayed", async () => {
    const a = signingFixture(11, "fortress-a");
    const aStorage = new MemoryStorage();
    const aMaster = new Uint8Array(32).fill(12);
    const aAdapter = new SdwMemoryBackendAdapter({
      storage: aStorage, masterKey: aMaster, fortressId: "fortress-a", ownerRef: "owner-a",
      now: () => NOW, resolvePrimarySigningHandle: () => a.handle,
      resolveSignerPublicKey: (identityId, did) => identityId === a.handle.identity_id && did === a.handle.did
        ? a.handle.public_key : undefined,
      resolveMemoryIntegrityState: async () => "state_COMPLETE",
    });
    await ingestClaudeCodeMemoryDirectory(aAdapter, CLAUDE_FIXTURE, { ingestedAt: NOW });
    const projection = await tempDir("exit-v2-direct-source");
    const archive = await transcodeMemoryDirectory(aAdapter, "claude-code", "codex",
      join(projection, "projection"), { now: () => NOW });
    const exportA = await exportExitV2SdwMemoryArchive({
      adapter: aAdapter, archiveId: archive.archive_id, sourceFortressId: "fortress-a",
      exportApprovalAuditId: "audit-a", sourceSanctuaryVersion: "1.7.2",
      signer: a.signer, formatVersion: 2,
      resolveProvenanceSigner: (_identityId, did) => did === a.handle.did ? a.handle.public_key : undefined,
      now: () => NOW,
    });

    const b = signingFixture(21, "fortress-b");
    const bStorage = new MemoryStorage();
    const bMaster = new Uint8Array(32).fill(22);
    const bKnown = new KnownSignersStore(bStorage, bMaster, { partition: "memory_provenance" });
    const bRuntime = new Map<string, Uint8Array>();
    const makeBAdapter = () => new SdwMemoryBackendAdapter({
      storage: bStorage, masterKey: bMaster, fortressId: "fortress-b", ownerRef: "owner-a",
      now: () => NOW, resolvePrimarySigningHandle: () => b.handle,
      resolveSignerPublicKey: (identityId, did) => identityId === b.handle.identity_id && did === b.handle.did
        ? b.handle.public_key : bRuntime.get(did),
      resolveMemoryIntegrityState: async () => "state_COMPLETE",
    });
    let bAdapter = makeBAdapter();
    const importedB = await importExitV2SdwMemoryArchive({
      adapter: bAdapter, signer: b.signer, knownSignersStore: bKnown,
      manifest: exportA.manifest, artifactBytes: exportA.artifact_bytes,
      transferKey: exportA.transfer_key.slice(), now: () => NOW,
      onProvenanceSignerPersisted: (did, key) => bRuntime.set(did, key),
    });
    const bFiles = (await bAdapter.listPassages({})).filter((p) => p.tags.includes("memory_transcode_file"));
    const directOrigins = await Promise.all(bFiles.map((p) => bAdapter.getPassageProvenance(p.passage_id)));
    expect(directOrigins.every((p) => p.status === "verified" &&
      p.companion.admission.body.origin_trust_tier === "foreign_direct")).toBe(true);
    const originalSignatures = directOrigins.map((p) => p.status === "verified" ? p.companion.origin.signature : "");

    // Restart: rebuild the synchronous resolver solely from bounded persisted state.
    bRuntime.clear();
    for (const row of await bKnown.loadAll()) bRuntime.set(row.did, row.publicKey);
    bAdapter = makeBAdapter();
    const exportB = await exportExitV2SdwMemoryArchive({
      adapter: bAdapter, archiveId: importedB.destination_archive_id,
      sourceFortressId: "fortress-b", exportApprovalAuditId: "audit-b",
      sourceSanctuaryVersion: "1.7.2", signer: b.signer, formatVersion: 2,
      resolveProvenanceSigner: (identityId, did) => identityId === b.handle.identity_id && did === b.handle.did
        ? b.handle.public_key : bRuntime.get(did), now: () => NOW,
    });

    const c = signingFixture(31, "fortress-c");
    const cStorage = new MemoryStorage();
    const cMaster = new Uint8Array(32).fill(32);
    const cKnown = new KnownSignersStore(cStorage, cMaster, { partition: "memory_provenance" });
    const cRuntime = new Map<string, Uint8Array>();
    const cAdapter = new SdwMemoryBackendAdapter({
      storage: cStorage, masterKey: cMaster, fortressId: "fortress-c", ownerRef: "owner-a",
      now: () => NOW, resolvePrimarySigningHandle: () => c.handle,
      resolveSignerPublicKey: (identityId, did) => identityId === c.handle.identity_id && did === c.handle.did
        ? c.handle.public_key : cRuntime.get(did),
      resolveMemoryIntegrityState: async () => "state_COMPLETE",
    });
    await importExitV2SdwMemoryArchive({
      adapter: cAdapter, signer: c.signer, knownSignersStore: cKnown,
      manifest: exportB.manifest, artifactBytes: exportB.artifact_bytes,
      transferKey: exportB.transfer_key.slice(), now: () => NOW,
      onProvenanceSignerPersisted: (did, key) => cRuntime.set(did, key),
    });
    const cFiles = (await cAdapter.listPassages({})).filter((p) => p.tags.includes("memory_transcode_file"));
    const relayed = await Promise.all(cFiles.map((p) => cAdapter.getPassageProvenance(p.passage_id)));
    expect(relayed.every((p) => p.status === "verified" &&
      p.companion.admission.body.origin_trust_tier === "foreign_relayed")).toBe(true);
    expect(relayed.map((p) => p.status === "verified" ? p.companion.origin.signature : "").sort())
      .toEqual(originalSignatures.sort());
  });

  it("blocks signed-memory export and both admission gates until C3 is COMPLETE", async () => {
    const incomplete = await makeSourceArchive();
    const sourceDeps = testMemoryProvenanceDependencies(new Uint8Array(32).fill(41));
    await expect(exportExitV2SdwMemoryArchive({
      adapter: incomplete.adapter, archiveId: incomplete.archiveId,
      sourceFortressId: "fortress-source", exportApprovalAuditId: "audit-incomplete",
      sourceSanctuaryVersion: "1.7.2", signer: makeSigner("fortress-source"),
      formatVersion: 2, resolveProvenanceSigner: sourceDeps.resolveSignerPublicKey,
    })).rejects.toThrow(/requires completed provenance migration/);

    const complete = await makeSourceArchive("owner-a", "state_COMPLETE");
    const exported = await exportExitV2SdwMemoryArchive({
      adapter: complete.adapter, archiveId: complete.archiveId,
      sourceFortressId: "fortress-source", exportApprovalAuditId: "audit-complete",
      sourceSanctuaryVersion: "1.7.2", signer: makeSigner("fortress-source"),
      formatVersion: 2, resolveProvenanceSigner: sourceDeps.resolveSignerPublicKey,
    });
    const destination = await makeAdapter({
      prefix: "exit-v2-incomplete-destination", ownerRef: "owner-a", masterByte: 99,
      fortressId: "fortress-destination", integrityState: "state_PRE_MIGRATION",
    });
    const destinationSigner = makeSigner("fortress-destination");
    await expect(planExitV2SdwMemoryAdmission({
      adapter: destination, signer: destinationSigner, manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes, transferKey: exported.transfer_key.slice(),
    })).rejects.toThrow(/preflight requires completed provenance migration/);
    await expect(importExitV2SdwMemoryArchive({
      adapter: destination, signer: destinationSigner,
      knownSignersStore: new KnownSignersStore(new MemoryStorage(), new Uint8Array(32).fill(99),
        { partition: "memory_provenance" }),
      manifest: exported.manifest, artifactBytes: exported.artifact_bytes,
      transferKey: exported.transfer_key.slice(),
    })).rejects.toThrow(/requires completed provenance migration/);
    expect(await destination.countPassages()).toBe(0);
  });

  it("fails wrong-key, tamper, and AAD mutations before any destination write", async () => {
    const source = await makeSourceArchive();
    const exported = await exportArchive(source);
    const destination = await makeAdapter({
      prefix: "exit-v2-fail-before",
      ownerRef: "owner-a",
      masterByte: 78,
      fortressId: "fortress-destination",
    });
    const before = await destination.countPassages();
    const signer = makeSigner("fortress-destination");

    const wrongKey = new Uint8Array(32).fill(255);
    await expect(importExitV2SdwMemoryArchive({
      adapter: destination,
      manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: wrongKey,
      signer,
    })).rejects.toThrow("Exit V2 SDW memory archive authentication failed");
    expect(wrongKey).toEqual(new Uint8Array(32));
    expect(await destination.countPassages()).toBe(before);

    const tampered = exported.artifact_bytes.slice();
    tampered[tampered.length - 2] ^= 1;
    const tamperKey = exported.transfer_key.slice();
    await expect(importExitV2SdwMemoryArchive({
      adapter: destination,
      manifest: exported.manifest,
      artifactBytes: tampered,
      transferKey: tamperKey,
      signer,
    })).rejects.toThrow("artifact hash or size is invalid");
    expect(tamperKey).toEqual(new Uint8Array(32));
    expect(await destination.countPassages()).toBe(before);

    const aadMutatedManifest = structuredClone(exported.manifest) as ExitV2SdwMemoryManifest;
    (aadMutatedManifest.body as { export_approval_audit_id: string })
      .export_approval_audit_id = "audit-different";
    const aadKey = exported.transfer_key.slice();
    await expect(importExitV2SdwMemoryArchive({
      adapter: destination,
      manifest: aadMutatedManifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: aadKey,
      signer,
    })).rejects.toThrow("manifest signature is invalid");
    expect(aadKey).toEqual(new Uint8Array(32));
    expect(await destination.countPassages()).toBe(before);
  });

  it("submits exactly one fail-before batch and leaves no archive or lineage on write failure", async () => {
    const source = await makeSourceArchive();
    const exported = await exportArchive(source);
    const destination = await makeAdapter({
      prefix: "exit-v2-atomic-failure",
      ownerRef: "owner-a",
      masterByte: 80,
      fortressId: "fortress-destination",
    });
    const before = await destination.countPassages();
    let putCalls = 0;
    const failingAdapter: MemoryBackendAdapter = new Proxy(destination, {
      get(target, property, receiver): unknown {
        if (property === "putPassagesIfAbsent") {
          return async (inputs: readonly MemoryPassageInput[]) => {
            putCalls++;
            expect(inputs).toHaveLength(5);
            expect(inputs.at(-1)?.tags).toContain("memory_transcode_lineage");
            throw new Error("injected atomic batch failure");
          };
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const key = exported.transfer_key.slice();
    await expect(importExitV2SdwMemoryArchive({
      adapter: failingAdapter,
      manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: key,
      signer: makeSigner("fortress-destination"),
    })).rejects.toThrow("injected atomic batch failure");
    expect(key).toEqual(new Uint8Array(32));
    expect(putCalls).toBe(1);
    expect(await destination.countPassages()).toBe(before);
  });

  it("rejects malformed inner path, digest, and count bindings before destination writes", async () => {
    const source = await makeSourceArchive();
    const sourceSigner = makeSigner("fortress-source");
    const exported = await exportArchive(source, sourceSigner);
    const originalArtifact = JSON.parse(
      Buffer.from(exported.artifact_bytes).toString("utf8"),
    ) as ExitV2SdwMemoryArtifact;
    const plaintext = decrypt(
      originalArtifact.encrypted_payload,
      exported.transfer_key,
      canonicalizeToBytes(originalArtifact.aad),
    );
    const originalPayload = JSON.parse(
      Buffer.from(plaintext).toString("utf8"),
    ) as ExitV2SdwMemoryLogicalPayload;
    plaintext.fill(0);
    type MutablePayload = {
      source_file_count: number;
      projection_file_count: number;
      files: Array<{ path: string; sha256: string }>;
    };
    const mutations: readonly {
      readonly name: string;
      readonly apply: (payload: MutablePayload) => void;
    }[] = [
      { name: "unsafe path", apply: (payload) => { payload.files[0]!.path = "../escape.md"; } },
      { name: "file digest", apply: (payload) => { payload.files[0]!.sha256 = "0".repeat(64); } },
      { name: "file count", apply: (payload) => { payload.source_file_count += 1; } },
      { name: "projection count", apply: (payload) => { payload.projection_file_count = 501; } },
    ];

    for (const mutation of mutations) {
      const destination = await makeAdapter({
        prefix: `exit-v2-inner-${mutation.name.replace(" ", "-")}`,
        ownerRef: "owner-a",
        masterByte: 81,
        fortressId: "fortress-destination",
      });
      const payload = structuredClone(originalPayload) as unknown as MutablePayload;
      mutation.apply(payload);
      const artifact: ExitV2SdwMemoryArtifact = {
        ...originalArtifact,
        encrypted_payload: encrypt(
          canonicalizeToBytes(payload),
          exported.transfer_key,
          canonicalizeToBytes(originalArtifact.aad),
        ),
      };
      const artifactBytes = canonicalizeToBytes(artifact);
      const manifest = structuredClone(exported.manifest) as ExitV2SdwMemoryManifest;
      const mutableBody = manifest.body as unknown as {
        artifacts: [{ hash: string; size_bytes: number }];
        artifacts_aggregate_hash: string;
      };
      mutableBody.artifacts[0].hash = sha256Hex(artifactBytes);
      mutableBody.artifacts[0].size_bytes = artifactBytes.byteLength;
      mutableBody.artifacts_aggregate_hash = sha256Hex(
        canonicalizeToBytes(manifest.body.artifacts),
      );
      (manifest as unknown as { signature: string }).signature = toBase64url(
        await sourceSigner.sign(canonicalizeToBytes(manifest.body)),
      );
      const key = exported.transfer_key.slice();
      await expect(importExitV2SdwMemoryArchive({
        adapter: destination,
        manifest,
        artifactBytes,
        transferKey: key,
        signer: makeSigner("fortress-destination"),
      }), mutation.name).rejects.toThrow(/logical (file|payload|source-set)/);
      expect(key).toEqual(new Uint8Array(32));
      expect(await destination.countPassages()).toBe(0);
    }
  });

  it("is idempotent only for the exact digest and rejects conflicting lineage before writes", async () => {
    const source = await makeSourceArchive();
    const exported = await exportArchive(source);
    const destination = await makeAdapter({
      prefix: "exit-v2-replay",
      ownerRef: "owner-a",
      masterByte: 79,
      fortressId: "fortress-destination",
    });
    const signer = makeSigner("fortress-destination");
    const first = await importExitV2SdwMemoryArchive({
      adapter: destination,
      manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: exported.transfer_key.slice(),
      signer,
      now: () => NOW,
    });
    const afterFirst = await destination.countPassages();
    const replay = await importExitV2SdwMemoryArchive({
      adapter: destination,
      manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: exported.transfer_key.slice(),
      signer,
    });
    expect(replay).toEqual({ ...first, replayed: true });
    expect(await destination.countPassages()).toBe(afterFirst);

    const conflicting = await exportArchive(source);
    await expect(importExitV2SdwMemoryArchive({
      adapter: destination,
      manifest: conflicting.manifest,
      artifactBytes: conflicting.artifact_bytes,
      transferKey: conflicting.transfer_key.slice(),
      signer,
    })).rejects.toThrow("source lineage already maps to a different artifact digest");
    expect(await destination.countPassages()).toBe(afterFirst);
  });

  it("binds exact replay lineage to the supplied destination signer identity", async () => {
    const source = await makeSourceArchive();
    const exported = await exportArchive(source);
    const alternateDestination = await makeAdapter({
      prefix: "exit-v2-alternate-signer-replay",
      ownerRef: "owner-a",
      masterByte: 81,
      fortressId: "fortress-destination",
    });
    const alternateSigner = makeSigner("fortress-destination");
    await importExitV2SdwMemoryArchive({
      adapter: alternateDestination,
      manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: exported.transfer_key.slice(),
      signer: alternateSigner,
      now: () => NOW,
    });
    const afterAlternateImport = await alternateDestination.countPassages();
    await expect(importExitV2SdwMemoryArchive({
      adapter: alternateDestination,
      manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: exported.transfer_key.slice(),
      signer: makeSigner("fortress-destination"),
    })).rejects.toThrow("replay lineage does not match the imported artifact");
    expect(await alternateDestination.countPassages()).toBe(afterAlternateImport);

    const didDestination = await makeAdapter({
      prefix: "exit-v2-did-binding-replay",
      ownerRef: "owner-a",
      masterByte: 82,
      fortressId: "fortress-destination",
    });
    const canonicalDidSigner = makeSigner("fortress-destination");
    const legacyDidSigner: ExitV2MemorySigner = {
      ...canonicalDidSigner,
      did: legacyPublicKeyToDid(fromBase64url(canonicalDidSigner.public_key)),
    };
    await importExitV2SdwMemoryArchive({
      adapter: didDestination,
      manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: exported.transfer_key.slice(),
      signer: legacyDidSigner,
      now: () => NOW,
    });
    const afterLegacyDidImport = await didDestination.countPassages();
    await expect(importExitV2SdwMemoryArchive({
      adapter: didDestination,
      manifest: exported.manifest,
      artifactBytes: exported.artifact_bytes,
      transferKey: exported.transfer_key.slice(),
      signer: canonicalDidSigner,
    })).rejects.toThrow("replay lineage does not match the imported artifact");
    expect(await didDestination.countPassages()).toBe(afterLegacyDidImport);
  });

  it("linearizes concurrent exact-digest imports instead of replacing lineage", async () => {
    const source = await makeSourceArchive();
    const exported = await exportArchive(source);
    const destination = await makeAdapter({
      prefix: "exit-v2-concurrent-replay",
      ownerRef: "owner-a",
      masterByte: 83,
      fortressId: "fortress-destination",
    });
    const signer = makeSigner("fortress-destination");
    const racingAdapter = synchronizeInitialPassageReads(destination);

    const receipts = await Promise.all([
      importExitV2SdwMemoryArchive({
        adapter: racingAdapter,
        manifest: exported.manifest,
        artifactBytes: exported.artifact_bytes,
        transferKey: exported.transfer_key.slice(),
        signer,
        now: () => "2026-08-15T06:31:00.000Z",
      }),
      importExitV2SdwMemoryArchive({
        adapter: racingAdapter,
        manifest: exported.manifest,
        artifactBytes: exported.artifact_bytes,
        transferKey: exported.transfer_key.slice(),
        signer,
        now: () => "2026-08-15T06:32:00.000Z",
      }),
    ]);
    expect(receipts.map((receipt) => receipt.replayed).sort()).toEqual([false, true]);
    expect(receipts[0]?.destination_archive_id).toBe(receipts[1]?.destination_archive_id);
    expect(await destination.countPassages()).toBe(5);
  });

  it("rejects a concurrent alternate signer instead of replacing the winning lineage", async () => {
    const source = await makeSourceArchive();
    const exported = await exportArchive(source);
    const destination = await makeAdapter({
      prefix: "exit-v2-concurrent-alternate-signer",
      ownerRef: "owner-a",
      masterByte: 84,
      fortressId: "fortress-destination",
    });
    const racingAdapter = synchronizeInitialPassageReads(destination);
    const results = await Promise.allSettled([
      importExitV2SdwMemoryArchive({
        adapter: racingAdapter,
        manifest: exported.manifest,
        artifactBytes: exported.artifact_bytes,
        transferKey: exported.transfer_key.slice(),
        signer: makeSigner("fortress-destination"),
        now: () => "2026-08-15T06:33:00.000Z",
      }),
      importExitV2SdwMemoryArchive({
        adapter: racingAdapter,
        manifest: exported.manifest,
        artifactBytes: exported.artifact_bytes,
        transferKey: exported.transfer_key.slice(),
        signer: makeSigner("fortress-destination"),
        now: () => "2026-08-15T06:34:00.000Z",
      }),
    ]);
    const fulfilled = results.filter((result) => result.status === "fulfilled");
    const rejected = results.filter((result) => result.status === "rejected");
    expect(fulfilled).toHaveLength(1);
    expect(fulfilled[0]).toMatchObject({ value: { replayed: false } });
    expect(rejected).toHaveLength(1);
    expect(rejected[0]).toMatchObject({
      reason: expect.objectContaining({
        message: "Exit V2 SDW memory replay lineage does not match the imported artifact",
      }),
    });
    expect(await destination.countPassages()).toBe(5);
  });

  it("linearizes concurrent conflicting artifacts through one source-lineage slot", async () => {
    const source = await makeSourceArchive();
    const firstExport = await exportArchive(source);
    const conflictingExport = await exportArchive(source);
    expect(conflictingExport.source_lineage_ref).toBe(firstExport.source_lineage_ref);
    expect(conflictingExport.artifact_sha256).not.toBe(firstExport.artifact_sha256);
    const destination = await makeAdapter({
      prefix: "exit-v2-concurrent-conflicting-artifact",
      ownerRef: "owner-a",
      masterByte: 85,
      fortressId: "fortress-destination",
    });
    const racingAdapter = synchronizeInitialPassageReads(destination);
    const signer = makeSigner("fortress-destination");
    const results = await Promise.allSettled([
      importExitV2SdwMemoryArchive({
        adapter: racingAdapter,
        manifest: firstExport.manifest,
        artifactBytes: firstExport.artifact_bytes,
        transferKey: firstExport.transfer_key.slice(),
        signer,
        now: () => "2026-08-15T06:35:00.000Z",
      }),
      importExitV2SdwMemoryArchive({
        adapter: racingAdapter,
        manifest: conflictingExport.manifest,
        artifactBytes: conflictingExport.artifact_bytes,
        transferKey: conflictingExport.transfer_key.slice(),
        signer,
        now: () => "2026-08-15T06:36:00.000Z",
      }),
    ]);
    const fulfilled = results.filter((result) => result.status === "fulfilled");
    const rejected = results.filter((result) => result.status === "rejected");
    expect(fulfilled).toHaveLength(1);
    expect(fulfilled[0]).toMatchObject({ value: { replayed: false } });
    expect(rejected).toHaveLength(1);
    expect(rejected[0]).toMatchObject({
      reason: expect.objectContaining({
        message:
          "Exit V2 SDW memory source lineage already maps to a different artifact digest",
      }),
    });
    // Only the winning artifact's three files, manifest, and shared lineage land.
    expect(await destination.countPassages()).toBe(5);
  });

  it("keeps source and destination owner scopes isolated", async () => {
    const storageRoot = await tempDir("exit-v2-owner-isolation-source");
    const ownerA = await makeAdapter({
      prefix: "unused",
      storageRoot,
      ownerRef: "owner-a",
      masterByte: 91,
      fortressId: "fortress-source",
    });
    const ownerB = await makeAdapter({
      prefix: "unused",
      storageRoot,
      ownerRef: "owner-b",
      masterByte: 91,
      fortressId: "fortress-source",
    });
    await ingestClaudeCodeMemoryDirectory(ownerA, CLAUDE_FIXTURE, { ingestedAt: NOW });
    await ingestClaudeCodeMemoryDirectory(ownerB, CLAUDE_FIXTURE, { ingestedAt: NOW });
    const projectionParent = await tempDir("exit-v2-owner-a-projection");
    const archive = await transcodeMemoryDirectory(
      ownerA,
      "claude-code",
      "codex",
      join(projectionParent, "projection"),
      { now: () => NOW },
    );
    const ownerBBefore = await ownerB.countPassages();
    await exportExitV2SdwMemoryArchive({
      adapter: ownerA,
      archiveId: archive.archive_id,
      sourceFortressId: "fortress-source",
      exportApprovalAuditId: "audit-owner-a",
      sourceSanctuaryVersion: "1.7.2",
      signer: makeSigner("fortress-source"),
    });
    expect(await ownerB.countPassages()).toBe(ownerBBefore);
    await expect(exportExitV2SdwMemoryArchive({
      adapter: ownerB,
      archiveId: archive.archive_id,
      sourceFortressId: "fortress-source",
      exportApprovalAuditId: "audit-owner-b",
      sourceSanctuaryVersion: "1.7.2",
      signer: makeSigner("fortress-source"),
    })).rejects.toThrow("archive manifest was not found");
  });

  it("participant Exit retains SDW archives and reports memory portability incomplete", async () => {
    const source = await makeSourceArchive();
    const receipt = await participantExitSdwMemoryRetention({
      adapter: source.adapter,
      sourceFortressId: "fortress-source",
    });
    expect(receipt).toEqual({
      memory_portability_complete: false,
      retained_sdw_archive_count: 1,
      retained_source_lineage_refs: [expect.stringMatching(/^[a-f0-9]{64}$/)],
    });
    expect(JSON.stringify(receipt)).not.toContain(source.archiveId);
    expect(JSON.stringify(receipt)).not.toContain(source.adapter.ownerRef);

    const rawOnly = await makeAdapter({
      prefix: "exit-v2-participant-raw-only",
      ownerRef: "owner-a",
      masterByte: 82,
      fortressId: "fortress-source",
    });
    await ingestClaudeCodeMemoryDirectory(rawOnly, CLAUDE_FIXTURE, { ingestedAt: NOW });
    await expect(participantExitSdwMemoryRetention({
      adapter: rawOnly,
      sourceFortressId: "fortress-source",
    })).resolves.toEqual({
      memory_portability_complete: false,
      retained_sdw_archive_count: 0,
      retained_source_lineage_refs: [],
    });
  });

  it("contains no watcher, scheduler, daemon, network, retry, or argv key surface", async () => {
    const source = await readFile(
      fileURLToPath(new URL("../../src/exit/v2-memory-archive.ts", import.meta.url)),
      "utf8",
    );
    for (const forbidden of [
      "setInterval(",
      "setTimeout(",
      "fetch(",
      "node:http",
      "node:https",
      "node:net",
      "process.argv",
      "--transfer-key",
      "console.",
      "logger.",
      "auditLog",
      "dashboard",
      "retry",
    ]) {
      expect(source).not.toContain(forbidden);
    }
  });
});
