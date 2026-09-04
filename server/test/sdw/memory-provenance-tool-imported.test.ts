/**
 * `sdw_memory_provenance` over passages admitted through a cross-fortress
 * memory archive import.
 *
 * Capability under test: an imported passage reports `verified` with its
 * foreign origin-trust tier and the transfer lineage reference of the import
 * that admitted it. The tool binds the foreign origin to the local passage
 * through the destination-signed admission written at import (the origin
 * digest it commits to, the local passage id it names, and the lineage
 * reference it carries). A companion presented for a passage it does not
 * describe is refused in both the local and the imported case, and a locally
 * authored passage reports exactly what it reported before. Both import
 * shapes are covered end to end: a signed-memory (V2) archive whose origins
 * another fortress signed, and a legacy V1 archive whose origins this fortress
 * signed itself at import with the legacy-unattested tier.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { toBase64url } from "../../src/core/encoding.js";
import { publicKeyToDid } from "../../src/core/identity.js";
import {
  exportExitV2SdwMemoryArchive,
  importExitV2SdwMemoryArchive,
  type ExitV2MemorySigner,
  type ImportExitV2SdwMemoryArchiveResult,
} from "../../src/exit/v2-memory-archive.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import { KnownSignersStore } from "../../src/reputation/known-signers-store.js";
import { ingestClaudeCodeMemoryDirectory } from "../../src/sdw/adapters/claude-code-file-adapter.js";
import type { MemoryBackendAdapter, MemoryPassage } from "../../src/sdw/adapters/memory-backend.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { documentProvenanceKey } from "../../src/sdw/grammar.js";
import { memoryInsertIngress } from "../../src/sdw/memory-provenance-ingress.js";
import {
  MEMORY_TRANSPORT_ADMISSION_CHANNELS,
  computeMemoryOriginProvenanceDigest,
  type MemoryProvenanceCompanion,
  type MemoryProvenanceSigningHandle,
} from "../../src/sdw/memory-provenance-contract.js";
import {
  SDW_MEMORY_PROVENANCE_AUDIT_OPS,
  createSdwMemoryProvenanceTool,
} from "../../src/sdw/memory-provenance-tool.js";
import { transcodeMemoryDirectory } from "../../src/sdw/memory-transcode.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { assertSdwRawWriteAuthorized } from "../../src/sdw/write-gate.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const CLAUDE_FIXTURE = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/basic/", import.meta.url),
);
const NOW = "2026-09-03T09:00:00.000Z";
const OWNER_REF = "owner-a";
const FILE_TAG = "memory_transcode_file";

/** Test-only storage exposing its map so a stored record can be tampered at rest. */
class TamperableStorage implements StorageBackend {
  readonly data = new Map<string, Uint8Array>();
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    const checked = assertSdwRawWriteAuthorized(namespace, key, data);
    this.data.set(`${namespace}\0${key}`, new Uint8Array(checked));
  }
  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.data.get(`${namespace}\0${key}`) ?? null;
  }
  async delete(namespace: string, key: string): Promise<boolean> {
    return this.data.delete(`${namespace}\0${key}`);
  }
  async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    const entries: StorageEntryMeta[] = [];
    for (const [composite, data] of this.data) {
      const separator = composite.indexOf("\0");
      const ns = composite.slice(0, separator);
      const key = composite.slice(separator + 1);
      if (ns !== namespace || !key.startsWith(prefix)) continue;
      entries.push({ namespace, key, size_bytes: data.byteLength, modified_at: NOW });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }
  async exists(namespace: string, key: string): Promise<boolean> {
    return this.data.has(`${namespace}\0${key}`);
  }
  async totalSize(): Promise<number> {
    let total = 0;
    for (const value of this.data.values()) total += value.byteLength;
    return total;
  }
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
    signer: {
      identity_id: identityId, fortress_id: fortressId,
      public_key: toBase64url(publicKey), did,
      sign: (bytes) => ed25519.sign(bytes, privateKey),
    },
    handle: {
      identity_id: identityId, did, public_key: publicKey,
      sign: (bytes) => ed25519.sign(bytes, privateKey),
    },
  };
}

type AuditCall = { operation: string; result?: string; details?: Record<string, unknown> };

function makeAuditLog(): { log: AuditLog; calls: AuditCall[] } {
  const calls: AuditCall[] = [];
  const log = {
    async appendCritical(entry: AuditCall): Promise<void> {
      calls.push({ operation: entry.operation, result: entry.result, details: entry.details });
    },
  } as unknown as AuditLog;
  return { log, calls };
}

function parse(result: { content: Array<{ type: "text"; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function verifiedCompanion(
  provenance: Awaited<ReturnType<MemoryBackendAdapter["getPassageProvenance"]>>,
): MemoryProvenanceCompanion {
  if (provenance.status !== "verified") throw new Error(`expected verified, got ${provenance.status}`);
  return provenance.companion;
}

/**
 * Wraps the destination adapter so `getPassageProvenance(passageId)` returns
 * the substituted companion as `verified`. Everything else passes through.
 * This plants exactly the split the wrapper's binding check exists to catch:
 * a verified-looking companion that does not describe the passage in hand.
 */
function substitutingAdapter(
  target: MemoryBackendAdapter,
  substitute: (passageId: string) => MemoryProvenanceCompanion | undefined,
): MemoryBackendAdapter {
  return new Proxy(target, {
    get(inner, property, receiver): unknown {
      if (property === "getPassageProvenance") {
        return async (passageId: string) => {
          const swapped = substitute(passageId);
          if (swapped !== undefined) return { status: "verified" as const, companion: swapped };
          return inner.getPassageProvenance(passageId);
        };
      }
      const value = Reflect.get(inner, property, receiver) as unknown;
      return typeof value === "function" ? value.bind(inner) : value;
    },
  }) as MemoryBackendAdapter;
}

describe("sdw_memory_provenance over passages admitted by a memory archive import", () => {
  let destination: SdwMemoryBackendAdapter;
  let destinationStorage: TamperableStorage;
  let receipt: ImportExitV2SdwMemoryArchiveResult;
  let v1Receipt: ImportExitV2SdwMemoryArchiveResult;
  /** File passages whose origin fortress A signed (signed-memory V2 import). */
  let importedFiles: readonly MemoryPassage[];
  /** File passages admitted from a legacy V1 archive (origin signed by B itself). */
  let legacyFiles: readonly MemoryPassage[];
  const cleanup: Array<() => Promise<void>> = [];

  /** Rebuilds a companion's digest fields around an altered origin, so only signatures disagree. */
  function withOrigin(
    companion: MemoryProvenanceCompanion,
    body: MemoryProvenanceCompanion["origin"]["body"],
  ): MemoryProvenanceCompanion {
    const origin = { ...companion.origin, body };
    const digest = computeMemoryOriginProvenanceDigest(origin);
    return {
      ...companion,
      origin,
      origin_provenance_digest: digest,
      admission: { ...companion.admission, body: { ...companion.admission.body, origin_provenance_digest: digest } },
    };
  }

  beforeAll(async () => {
    const tempRoot = await realpath(await mkdtemp(join(tmpdir(), "prov-import-tool-")));
    cleanup.push(() => rm(tempRoot, { recursive: true, force: true }));

    // Fortress A authors the passages, transcodes them into an archive, and
    // exports it under its own signing key.
    const a = signingFixture(11, "fortress-a");
    const source = new SdwMemoryBackendAdapter({
      storage: new MemoryStorage(), masterKey: new Uint8Array(32).fill(12),
      fortressId: "fortress-a", ownerRef: OWNER_REF, now: () => NOW,
      resolvePrimarySigningHandle: () => a.handle,
      resolveSignerPublicKey: (identityId, did) =>
        identityId === a.handle.identity_id && did === a.handle.did ? a.handle.public_key : undefined,
      resolveMemoryIntegrityState: async () => "state_COMPLETE",
    });
    await ingestClaudeCodeMemoryDirectory(source, CLAUDE_FIXTURE, { ingestedAt: NOW });
    const archive = await transcodeMemoryDirectory(
      source, "claude-code", "codex", join(tempRoot, "projection"), { now: () => NOW },
    );
    const exported = await exportExitV2SdwMemoryArchive({
      adapter: source, archiveId: archive.archive_id, sourceFortressId: "fortress-a",
      exportApprovalAuditId: "audit-a", sourceSanctuaryVersion: "1.7.2",
      signer: a.signer, formatVersion: 2,
      resolveProvenanceSigner: (_identityId, did) =>
        did === a.handle.did ? a.handle.public_key : undefined,
      now: () => NOW,
    });

    // Fortress B imports it. Its resolver learns A's key only through the
    // import's known-signer persistence, as the shipped path does.
    const b = signingFixture(21, "fortress-b");
    destinationStorage = new TamperableStorage();
    const bMaster = new Uint8Array(32).fill(22);
    const bRuntime = new Map<string, Uint8Array>();
    destination = new SdwMemoryBackendAdapter({
      storage: destinationStorage, masterKey: bMaster, fortressId: "fortress-b",
      ownerRef: OWNER_REF, now: () => NOW,
      resolvePrimarySigningHandle: () => b.handle,
      resolveSignerPublicKey: (identityId, did) =>
        identityId === b.handle.identity_id && did === b.handle.did
          ? b.handle.public_key
          : bRuntime.get(did),
      resolveMemoryIntegrityState: async () => "state_COMPLETE",
    });
    receipt = await importExitV2SdwMemoryArchive({
      adapter: destination, signer: b.signer,
      knownSignersStore: new KnownSignersStore(new MemoryStorage(), bMaster, { partition: "memory_provenance" }),
      manifest: exported.manifest, artifactBytes: exported.artifact_bytes,
      transferKey: exported.transfer_key.slice(), now: () => NOW,
      onProvenanceSignerPersisted: (did, key) => bRuntime.set(did, key),
    });

    // Fortress C (pre-migration) exports the SAME fixture as a legacy V1
    // archive; B admits it with origins it signs itself at import.
    const c = signingFixture(31, "fortress-c");
    const legacySource = new SdwMemoryBackendAdapter({
      storage: new MemoryStorage(), masterKey: new Uint8Array(32).fill(32),
      fortressId: "fortress-c", ownerRef: OWNER_REF, now: () => NOW,
      resolvePrimarySigningHandle: () => c.handle,
      resolveSignerPublicKey: (identityId, did) =>
        identityId === c.handle.identity_id && did === c.handle.did ? c.handle.public_key : undefined,
      resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
    });
    await ingestClaudeCodeMemoryDirectory(legacySource, CLAUDE_FIXTURE, { ingestedAt: NOW });
    const legacyArchive = await transcodeMemoryDirectory(
      legacySource, "claude-code", "codex", join(tempRoot, "projection-c"), { now: () => NOW },
    );
    const legacyExport = await exportExitV2SdwMemoryArchive({
      adapter: legacySource, archiveId: legacyArchive.archive_id, sourceFortressId: "fortress-c",
      exportApprovalAuditId: "audit-c", sourceSanctuaryVersion: "1.7.2",
      signer: c.signer, now: () => NOW,
    });
    v1Receipt = await importExitV2SdwMemoryArchive({
      adapter: destination, signer: b.signer,
      manifest: legacyExport.manifest, artifactBytes: legacyExport.artifact_bytes,
      transferKey: legacyExport.transfer_key.slice(), now: () => NOW,
    });

    const files = (await destination.listPassages({})).filter((p) => p.tags.includes(FILE_TAG));
    const foreign: MemoryPassage[] = [];
    const legacy: MemoryPassage[] = [];
    for (const passage of files) {
      const companion = verifiedCompanion(await destination.getPassageProvenance(passage.passage_id));
      (companion.origin.body.origin_fortress_id === "fortress-a" ? foreign : legacy).push(passage);
    }
    importedFiles = foreign;
    legacyFiles = legacy;
    expect(importedFiles.length).toBeGreaterThanOrEqual(2);
    expect(legacyFiles.length).toBeGreaterThanOrEqual(2);
  });

  afterAll(async () => {
    while (cleanup.length > 0) await cleanup.pop()!();
  });

  it("fixture carries the imported shape: origin names the SOURCE passage id, admission names the LOCAL one", async () => {
    for (const passage of importedFiles) {
      const companion = verifiedCompanion(await destination.getPassageProvenance(passage.passage_id));
      expect(companion.origin.body.origin_fortress_id).toBe("fortress-a");
      expect(companion.origin.body.passage_id).not.toBe(passage.passage_id);
      expect(companion.admission.body.passage_id).toBe(passage.passage_id);
      expect(companion.admission.body.admission_channel).toBe("exit_v2_import");
      expect(MEMORY_TRANSPORT_ADMISSION_CHANNELS).toContain(companion.admission.body.admission_channel);
      expect(companion.admission.body.transfer_lineage_ref).toBe(receipt.source_lineage_ref);
    }
  });

  it("fixture carries the legacy V1 shape: a transport channel whose origin THIS fortress signed about the LOCAL id", async () => {
    for (const passage of legacyFiles) {
      const companion = verifiedCompanion(await destination.getPassageProvenance(passage.passage_id));
      expect(companion.origin.body.origin_fortress_id).toBe("fortress-b");
      expect(companion.origin.body.passage_id).toBe(passage.passage_id);
      expect(companion.admission.body).toMatchObject({
        passage_id: passage.passage_id,
        admission_channel: "exit_v2_import",
        origin_trust_tier: "legacy_unattested",
        verification_basis: "exit_v2_legacy_v1",
        transfer_lineage_ref: v1Receipt.source_lineage_ref,
      });
    }
  });

  it("(a-legacy) reports a legacy V1 import row verified with the legacy-unattested tier, its lineage, and a note that does not claim another fortress", async () => {
    const { log, calls } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({ adapter: destination, auditLog: log });
    for (const passage of legacyFiles) {
      const out = parse(await tool.handler({ passage_id: passage.passage_id }));
      expect(out.denied).toBeUndefined();
      expect(out.provenance_status).toBe("verified");
      const gaps = out.provenance_gaps as Record<string, unknown>;
      expect(gaps).toMatchObject({
        admission_channel: "exit_v2_import",
        origin_trust_tier: "legacy_unattested",
        verification_basis: "exit_v2_legacy_v1",
        transfer_lineage_ref: v1Receipt.source_lineage_ref,
      });
      expect(String(gaps.note)).not.toContain("another fortress");
      expect(String(gaps.note)).toContain("recorded the origin binding itself");
      expect(String(gaps.note)).toContain("does not prove true authorship");
    }
    expect(calls.filter((c) => c.operation === SDW_MEMORY_PROVENANCE_AUDIT_OPS.denied)).toEqual([]);
  });

  it("(b-legacy) a legacy V1 row's origin re-pointed at another local id, digests made consistent, is refused: the direct subject check is applied on a transport channel when the origin is local", async () => {
    const [l1, l2] = legacyFiles;
    const genuine = verifiedCompanion(await destination.getPassageProvenance(l2!.passage_id));
    const forged = withOrigin(genuine, { ...genuine.origin.body, passage_id: l1!.passage_id });
    const { log, calls } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({
      adapter: substitutingAdapter(destination, (id) => (id === l2!.passage_id ? forged : undefined)),
      auditLog: log,
    });
    const out = parse(await tool.handler({ passage_id: l2!.passage_id }));
    expect(out.denied).toBe(true);
    expect(calls[0]!.details).toEqual({ denial_class: "auth_failed" });
  });

  it("(b) a local-channel companion whose origin claims another fortress, digests made consistent, is refused", async () => {
    await destination.putPassages(
      [{ passage_id: "local-z", text: "authored here, z", provenanceContext: memoryInsertIngress(() => "system:test", "system_generated") }],
      "agent_derived_clean",
    );
    const genuine = verifiedCompanion(await destination.getPassageProvenance("local-z"));
    const forged = withOrigin(genuine, { ...genuine.origin.body, origin_fortress_id: "fortress-elsewhere" });
    const { log } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({
      adapter: substitutingAdapter(destination, (id) => (id === "local-z" ? forged : undefined)),
      auditLog: log,
    });
    const out = parse(await tool.handler({ passage_id: "local-z" }));
    expect(out.denied).toBe(true);
  });

  it("(a) reports every imported passage verified with the foreign tier and the import lineage reference", async () => {
    const { log, calls } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({ adapter: destination, auditLog: log });
    for (const passage of importedFiles) {
      const out = parse(await tool.handler({ passage_id: passage.passage_id }));
      expect(out.denied).toBeUndefined();
      expect(out.found).toBe(true);
      expect(out.provenance_status).toBe("verified");
      expect((out.provenance as Record<string, unknown>).passage_id).toBe(passage.passage_id);
      const gaps = out.provenance_gaps as Record<string, unknown>;
      expect(gaps).toMatchObject({
        signing_status: "verified",
        admission_channel: "exit_v2_import",
        origin_trust_tier: "foreign_direct",
        verification_basis: "exit_v2_manifest_key",
        transfer_lineage_ref: receipt.source_lineage_ref,
      });
      expect(String(gaps.note)).toContain("another fortress");
      expect(String(gaps.note)).toContain("names the transfer lineage");
      expect(String(gaps.note)).not.toContain("through the named transfer lineage");
      expect(String(gaps.note)).toContain("does not prove true authorship");
      // Public-safe projection holds for the imported case too.
      for (const forbidden of [
        "origin_fortress_id", "signer_did", "destination_fortress_id", "signature", "companion",
      ]) expect(gaps).not.toHaveProperty(forbidden);
      expect(JSON.stringify(out)).not.toContain("did:key:");
      expect(JSON.stringify(out)).not.toContain("fortress-a");
    }
    expect(calls.filter((c) => c.operation === SDW_MEMORY_PROVENANCE_AUDIT_OPS.denied)).toEqual([]);
    expect(calls.filter((c) => c.operation === SDW_MEMORY_PROVENANCE_AUDIT_OPS.read))
      .toHaveLength(importedFiles.length);
  });

  it("(b) a companion from local passage X presented for local passage Y is refused", async () => {
    await destination.putPassages(
      [{ passage_id: "local-x", text: "authored here, x", provenanceContext: memoryInsertIngress(() => "system:test", "system_generated") },
       { passage_id: "local-y", text: "authored here, y", provenanceContext: memoryInsertIngress(() => "system:test", "system_generated") }],
      "agent_derived_clean",
    );
    const companionX = verifiedCompanion(await destination.getPassageProvenance("local-x"));
    const { log, calls } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({
      adapter: substitutingAdapter(destination, (id) => (id === "local-y" ? companionX : undefined)),
      auditLog: log,
    });
    const out = parse(await tool.handler({ passage_id: "local-y" }));
    expect(out.denied).toBe(true);
    expect(out).not.toHaveProperty("provenance");
    expect(calls.map((c) => c.operation)).toEqual([SDW_MEMORY_PROVENANCE_AUDIT_OPS.denied]);
    expect(calls[0]!.details).toEqual({ denial_class: "auth_failed" });
  });

  it("(b) a whole companion from imported passage P1 presented for imported passage P2 is refused", async () => {
    const [p1, p2] = importedFiles;
    const companion1 = verifiedCompanion(await destination.getPassageProvenance(p1!.passage_id));
    const { log } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({
      adapter: substitutingAdapter(destination, (id) => (id === p2!.passage_id ? companion1 : undefined)),
      auditLog: log,
    });
    const out = parse(await tool.handler({ passage_id: p2!.passage_id }));
    expect(out.denied).toBe(true);
    expect(out).not.toHaveProperty("provenance");
  });

  it("(b) P2's own admission spliced onto P1's foreign origin is refused: the admission commits to ONE origin digest", async () => {
    const [p1, p2] = importedFiles;
    const companion1 = verifiedCompanion(await destination.getPassageProvenance(p1!.passage_id));
    const companion2 = verifiedCompanion(await destination.getPassageProvenance(p2!.passage_id));
    // Same local subject (P2's admission names P2, matching content hash is
    // NOT guaranteed, so also carry P2's hash into the presented origin to
    // isolate the digest binding as the refusing check).
    const spliced: MemoryProvenanceCompanion = {
      ...companion2,
      origin: {
        ...companion1.origin,
        body: {
          ...companion1.origin.body,
          content_hash: companion2.origin.body.content_hash,
          chunk_count: companion2.origin.body.chunk_count,
        },
      },
    };
    const { log } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({
      adapter: substitutingAdapter(destination, (id) => (id === p2!.passage_id ? spliced : undefined)),
      auditLog: log,
    });
    const out = parse(await tool.handler({ passage_id: p2!.passage_id }));
    expect(out.denied).toBe(true);
    expect(out).not.toHaveProperty("provenance");
  });

  it("(c) an import mapping with no lineage reference is refused, even when everything else matches", async () => {
    const [p1] = importedFiles;
    const genuine = verifiedCompanion(await destination.getPassageProvenance(p1!.passage_id));
    const { transfer_lineage_ref: _dropped, ...admissionWithoutLineage } = genuine.admission.body;
    const forged: MemoryProvenanceCompanion = {
      ...genuine,
      admission: { ...genuine.admission, body: admissionWithoutLineage as typeof genuine.admission.body },
    };
    const { log, calls } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({
      adapter: substitutingAdapter(destination, (id) => (id === p1!.passage_id ? forged : undefined)),
      auditLog: log,
    });
    const out = parse(await tool.handler({ passage_id: p1!.passage_id }));
    expect(out.denied).toBe(true);
    expect(calls[0]!.details).toEqual({ denial_class: "auth_failed" });
  });

  it("(c) an import mapping whose lineage reference is not a bounded identifier is refused (same predicate as the parser)", async () => {
    const [p1] = importedFiles;
    const genuine = verifiedCompanion(await destination.getPassageProvenance(p1!.passage_id));
    const forged: MemoryProvenanceCompanion = {
      ...genuine,
      admission: { ...genuine.admission, body: { ...genuine.admission.body, transfer_lineage_ref: "not a valid ref" } },
    };
    const { log } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({
      adapter: substitutingAdapter(destination, (id) => (id === p1!.passage_id ? forged : undefined)),
      auditLog: log,
    });
    const out = parse(await tool.handler({ passage_id: p1!.passage_id }));
    expect(out.denied).toBe(true);
    expect(out).not.toHaveProperty("provenance");
  });

  it("(c) an import mapping whose claimed origin digest does not match the presented origin is refused", async () => {
    const [p1] = importedFiles;
    const genuine = verifiedCompanion(await destination.getPassageProvenance(p1!.passage_id));
    const wrongDigest = genuine.origin_provenance_digest.replace(/^./, (c) => (c === "0" ? "1" : "0"));
    const forged: MemoryProvenanceCompanion = {
      ...genuine,
      origin_provenance_digest: wrongDigest,
      admission: { ...genuine.admission, body: { ...genuine.admission.body, origin_provenance_digest: wrongDigest } },
    };
    const { log } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({
      adapter: substitutingAdapter(destination, (id) => (id === p1!.passage_id ? forged : undefined)),
      auditLog: log,
    });
    const out = parse(await tool.handler({ passage_id: p1!.passage_id }));
    expect(out.denied).toBe(true);
    expect(out).not.toHaveProperty("provenance");
  });

  it("(c) an import mapping altered at rest never reaches verified: the backend quarantines and the tool says so", async () => {
    const [, , p3] = importedFiles;
    const target = p3 ?? importedFiles[importedFiles.length - 1]!;
    const suffix = `\0${documentProvenanceKey(`mem.${OWNER_REF}.${target.passage_id}`)}`;
    const key = [...destinationStorage.data.keys()].find(
      (k) => k.startsWith(`${SDW_DOCUMENT_CORPUS_NAMESPACE}\0`) && k.endsWith(suffix),
    );
    expect(key).toBeDefined();
    const stored = destinationStorage.data.get(key!)!;
    const altered = new Uint8Array(stored);
    altered[altered.length - 1] ^= 0xff;
    destinationStorage.data.set(key!, altered);
    const { log } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({ adapter: destination, auditLog: log });
    const out = parse(await tool.handler({ passage_id: target.passage_id }));
    expect(out.found).toBe(true);
    expect(out.provenance_status).toBe("quarantined");
    expect(out).not.toHaveProperty("provenance");
  });

  it("(d) a locally authored passage on the same fortress reports exactly the pre-existing local projection", async () => {
    await destination.putPassages(
      [{ passage_id: "local-only", text: "authored on fortress b", provenanceContext: memoryInsertIngress(() => "system:test", "system_generated") }],
      "agent_derived_clean",
    );
    const { log } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({ adapter: destination, auditLog: log });
    const out = parse(await tool.handler({ passage_id: "local-only" }));
    expect(out.provenance_status).toBe("verified");
    const gaps = out.provenance_gaps as Record<string, unknown>;
    expect(gaps).toMatchObject({
      admission_channel: "local_write",
      origin_trust_tier: "local_attested",
      verification_basis: "local_primary_identity",
    });
    expect(gaps).not.toHaveProperty("transfer_lineage_ref");
    expect(String(gaps.note)).toContain("The fortress-recorded origin and admission bindings verify for this exact passage.");
    expect(Object.keys(gaps).sort()).toEqual([
      "admission_channel", "admitted_at", "automatic_provenance_event", "ingress_channel", "note",
      "origin_trust_tier", "per_writer_signature", "recorded_at", "signing_status", "source_class",
      "taint_retrievable", "verification_basis",
    ]);
  });
});
