import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { publicKeyToDid } from "../../src/core/identity.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  KNOWN_SIGNERS_NAMESPACE,
  KnownSignersStore,
  knownSignerStorageKey,
} from "../../src/reputation/known-signers-store.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import {
  documentKey,
  documentProvenanceKey,
  documentProvenanceStatusKey,
} from "../../src/sdw/grammar.js";
import {
  MemoryProvenanceBadSignerStore,
  memoryProvenancePublicKeyFingerprint,
} from "../../src/sdw/memory-provenance-bad-signers.js";
import {
  MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE_AUDIT,
  MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN_AUDIT,
  MemoryProvenanceSignerPruner,
} from "../../src/sdw/memory-provenance-signer-prune.js";
import { createMemoryProvenanceSignerPruneTool } from "../../src/sdw/memory-provenance-signer-prune-tools.js";
import { signMemoryOrigin } from "../../src/sdw/memory-provenance-contract.js";
import { exitV2ForeignImportIngress } from "../../src/sdw/memory-provenance-ingress.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { passageContentHash } from "../../src/sdw/write-gate.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE } from "../../src/storage/exit-import-journal.js";
import type { StorageEntryMeta } from "../../src/storage/interface.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { testMemoryProvenanceDependencies } from "./test-memory-backend.js";

const MASTER = new Uint8Array(32).fill(93);
const FORTRESS = "fortress:signer-prune";
const OWNER = "fleet-self";
const NOW = "2026-08-25T01:00:00.000Z";

class FaultStorage extends MemoryStorage {
  failAfterSignerDelete = false;
  tamperReadKey: string | null = null;
  mutateCorpusOnRelist = false;
  corpusLists = 0;
  syntheticOverCap = false;
  vanishReadKey: string | null = null;
  reads = 0;

  override async read(namespace: string, key: string): Promise<Uint8Array | null> {
    this.reads++;
    if (key === this.vanishReadKey) return null;
    const value = await super.read(namespace, key);
    if (value !== null && key === this.tamperReadKey) value[0] ^= 1;
    return value;
  }

  override async delete(namespace: string, key: string, secure?: boolean): Promise<boolean> {
    const deleted = await super.delete(namespace, key, secure);
    if (namespace === KNOWN_SIGNERS_NAMESPACE && deleted && this.failAfterSignerDelete) {
      this.failAfterSignerDelete = false;
      throw new Error("injected post-delete fault");
    }
    return deleted;
  }

  override async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE && prefix === "doc.mem." &&
        this.syntheticOverCap) {
      return Array.from({ length: 2_001 }, (_, index) => ({
        namespace,
        key: `doc.mem.${OWNER}.synthetic-${String(index)}`,
        size_bytes: 1,
        modified_at: NOW,
      }));
    }
    const listed = await super.list(namespace, prefix);
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE) {
      this.corpusLists++;
      if (this.mutateCorpusOnRelist && this.corpusLists === 4 && prefix === "doc.mem.") {
        return [...listed, {
          namespace,
          key: `doc.mem.${OWNER}.raced`,
          size_bytes: 1,
          modified_at: NOW,
        }];
      }
    }
    return listed;
  }
}

function foreign(seedByte: number, id: string, text: string, tier: "foreign_direct" | "foreign_relayed") {
  const seed = new Uint8Array(32).fill(seedByte);
  const publicKey = ed25519.getPublicKey(seed);
  const did = publicKeyToDid(publicKey);
  const origin = signMemoryOrigin({
    origin_fortress_id: `foreign-${id}`,
    owner_ref: "source-owner",
    passage_id: `source-${id}`,
    content_hash: passageContentHash(text),
    chunk_count: 1,
    author_agent_id: `agent-${id}`,
    ingress_channel: "memory_insert",
    source_class: "user_content",
    recorded_at: NOW,
  }, {
    identity_id: id,
    did,
    public_key: publicKey,
    sign: (bytes) => ed25519.sign(bytes, seed),
  });
  if (!origin.ok) throw new Error(origin.error.message);
  return { id, did, publicKey, text, tier, origin: origin.value };
}

async function fixture() {
  const storage = new FaultStorage();
  const local = testMemoryProvenanceDependencies(MASTER);
  const direct = foreign(81, "direct-id", "direct text", "foreign_direct");
  const relayed = foreign(82, "relayed-id", "relayed text", "foreign_relayed");
  const unusedA = foreign(83, "unused-a", "unused a", "foreign_direct");
  const unusedB = foreign(84, "unused-b", "unused b", "foreign_direct");
  const all = [direct, relayed, unusedA, unusedB];
  const keys = new Map(all.map((entry) => [entry.did, entry.publicKey]));
  const known = new KnownSignersStore(storage, MASTER, { partition: "memory_provenance" });
  await known.persistIfAbsent(all.map((entry) => ({ did: entry.did, publicKey: entry.publicKey })), "fixture");
  let adapter!: SdwMemoryBackendAdapter;
  const bad = new MemoryProvenanceBadSignerStore({
    storage,
    masterKey: MASTER,
    fortressId: FORTRESS,
    resolveSignerPublicKey: (did) => keys.get(did)?.slice(),
    isLocallyRootedSigner: () => false,
    scanForeignDependencies: (did, fingerprint) =>
      adapter.scanForeignSignerDependencies(did, fingerprint),
    now: () => NOW,
  });
  adapter = new SdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER,
    fortressId: FORTRESS,
    ownerRef: OWNER,
    maxChunkChars: 100,
    now: () => NOW,
    resolvePrimarySigningHandle: local.resolvePrimarySigningHandle,
    resolveSignerPublicKey: (identityId, did) =>
      keys.get(did)?.slice() ?? local.resolveSignerPublicKey(identityId, did),
    resolveMemoryIntegrityState: async () => "state_COMPLETE",
    badSignerAuthority: bad,
  });
  for (const entry of [direct, relayed]) {
    await adapter.insertPassage({
      passage_id: entry.id,
      text: entry.text,
      provenanceContext: exitV2ForeignImportIngress({
        origin: entry.origin,
        originPublicKey: entry.publicKey,
        trustTier: entry.tier,
        transferLineageRef: entry.id[0]!.repeat(64),
      }),
    }, "user_content");
  }
  const audit = new AuditLog(storage, MASTER);
  const pruner = new MemoryProvenanceSignerPruner({
    storage,
    masterKey: MASTER,
    fortressId: FORTRESS,
    knownSignersStore: known,
    resolveSignerPublicKey: (identityId, did) =>
      keys.get(did)?.slice() ?? local.resolveSignerPublicKey(identityId, did),
    forgetSigner: (did) => { keys.delete(did); },
    auditLog: audit,
  });
  return { storage, local, direct, relayed, unusedA, unusedB, keys, known, adapter, bad, audit, pruner };
}

describe("C4 memory-provenance signer mark-and-sweep", () => {
  it("retains direct, relayed, quarantined, and orphan-but-authenticated references and deletes only sorted zero-reference mappings", async () => {
    const f = await fixture();
    await f.bad.mark({
      signerDid: f.direct.did,
      publicKeySha256: memoryProvenancePublicKeyFingerprint(f.direct.publicKey),
      reason: "test quarantine",
      approvalAuditId: "gate-mark",
    }, f.audit);
    await f.storage.delete(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentKey(`mem.${OWNER}.${f.relayed.id}`),
      true,
    );

    const result = await f.pruner.prune({ approvalAuditId: "gate-prune" });
    expect(result.deleted.map((entry) => entry.signer_did)).toEqual(
      [f.unusedA.did, f.unusedB.did].sort(),
    );
    expect(result.exact_set_digest).toBe(
      "ef47c604756b39964545e4e152100045a78486cfc26a654a58c9063927b7b97f",
    );
    expect(await f.known.lookup(f.direct.did)).not.toBeNull();
    expect(await f.known.lookup(f.relayed.did)).not.toBeNull();
    expect(await f.known.lookup(f.unusedA.did)).toBeNull();
    expect(await f.known.lookup(f.unusedB.did)).toBeNull();
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);

    const plan = await f.audit.query({
      operation_type: MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN_AUDIT,
      limit: 10,
    });
    const complete = await f.audit.query({
      operation_type: MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE_AUDIT,
      limit: 10,
    });
    expect(plan.entries).toHaveLength(1);
    expect(plan.entries[0]!.details).toMatchObject({
      approval_audit_id: "gate-prune",
      exact_set_digest: result.exact_set_digest,
      deletion_set: result.deleted,
    });
    expect(complete.entries).toHaveLength(1);
    // Four records and four signers stay within a fixed multiple of their
    // combined population: no records-by-signers cross product is performed.
    expect(f.storage.reads).toBeLessThan(100);
  });

  it("audits an empty complete plan without publishing a journal", async () => {
    const f = await fixture();
    await f.storage.delete(KNOWN_SIGNERS_NAMESPACE,
      knownSignerStorageKey(f.unusedA.did, "memory_provenance"), true);
    await f.storage.delete(KNOWN_SIGNERS_NAMESPACE,
      knownSignerStorageKey(f.unusedB.did, "memory_provenance"), true);
    const result = await f.pruner.prune({ approvalAuditId: "gate-empty" });
    expect(result.deleted).toEqual([]);
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    expect((await f.audit.query({ operation_type: MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN_AUDIT })).entries).toHaveLength(1);
    expect((await f.audit.query({ operation_type: MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE_AUDIT })).entries).toHaveLength(1);
  });

  it("restores exact signer bytes when deletion fails after removal", async () => {
    const f = await fixture();
    const key = knownSignerStorageKey(f.unusedA.did, "memory_provenance");
    const before = await f.storage.read(KNOWN_SIGNERS_NAMESPACE, key);
    f.storage.failAfterSignerDelete = true;
    await expect(f.pruner.prune({ approvalAuditId: "gate-fault" })).rejects.toThrow(
      /post-delete fault/,
    );
    expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, key)).toEqual(before);
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
  });

  it("refuses authenticated-state corruption and a changed re-list with zero deletion", async () => {
    const f = await fixture();
    const unusedKey = knownSignerStorageKey(f.unusedA.did, "memory_provenance");
    const before = await f.storage.read(KNOWN_SIGNERS_NAMESPACE, unusedKey);
    f.storage.tamperReadKey = documentProvenanceKey(`mem.${OWNER}.${f.direct.id}`);
    await expect(f.pruner.prune({ approvalAuditId: "gate-corrupt" })).rejects.toThrow();
    expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, unusedKey)).toEqual(before);
    f.storage.tamperReadKey = null;
    f.storage.corpusLists = 0;
    f.storage.mutateCorpusOnRelist = true;
    await expect(f.pruner.prune({ approvalAuditId: "gate-race" })).rejects.toThrow(/changed/);
    expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, unusedKey)).toEqual(before);
  });

  it("refuses malformed or incomplete document, provenance, status, and signer scans", async () => {
    const corruptionTargets = ["document", "provenance", "status", "signer"] as const;
    for (const target of corruptionTargets) {
      const f = await fixture();
      f.keys.delete(f.direct.did);
      expect((await f.adapter.getPassageProvenance(f.direct.id)).status).toBe("quarantined");
      f.keys.set(f.direct.did, f.direct.publicKey);
      const unusedKey = knownSignerStorageKey(f.unusedA.did, "memory_provenance");
      const before = await f.storage.read(KNOWN_SIGNERS_NAMESPACE, unusedKey);
      const documentId = `mem.${OWNER}.${f.direct.id}`;
      f.storage.tamperReadKey = target === "document"
        ? documentKey(documentId)
        : target === "provenance"
          ? documentProvenanceKey(documentId)
          : target === "status"
            ? documentProvenanceStatusKey(documentId)
            : unusedKey;
      await expect(f.pruner.prune({ approvalAuditId: `gate-corrupt-${target}` })).rejects.toThrow();
      f.storage.tamperReadKey = null;
      expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, unusedKey)).toEqual(before);
    }

    for (const missingTarget of ["document", "provenance", "status"] as const) {
      const f = await fixture();
      f.keys.delete(f.direct.did);
      expect((await f.adapter.getPassageProvenance(f.direct.id)).status).toBe("quarantined");
      f.keys.set(f.direct.did, f.direct.publicKey);
      const documentId = `mem.${OWNER}.${f.direct.id}`;
      f.storage.vanishReadKey = missingTarget === "document"
        ? documentKey(documentId)
        : missingTarget === "provenance"
          ? documentProvenanceKey(documentId)
          : documentProvenanceStatusKey(documentId);
      const unusedKey = knownSignerStorageKey(f.unusedA.did, "memory_provenance");
      const before = await f.storage.read(KNOWN_SIGNERS_NAMESPACE, unusedKey);
      await expect(f.pruner.prune({ approvalAuditId: `gate-incomplete-${missingTarget}` }))
        .rejects.toThrow(/disappeared/);
      f.storage.vanishReadKey = null;
      expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, unusedKey)).toEqual(before);
    }
  });

  it("refuses an over-cap union before decoding or deleting", async () => {
    const f = await fixture();
    const key = knownSignerStorageKey(f.unusedA.did, "memory_provenance");
    const before = await f.storage.read(KNOWN_SIGNERS_NAMESPACE, key);
    f.storage.syntheticOverCap = true;
    await expect(f.pruner.prune({ approvalAuditId: "gate-cap" })).rejects.toThrow(/cap/);
    expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, key)).toEqual(before);
  });

  it("binds the real MCP tool to a gate-minted approval id", async () => {
    const f = await fixture();
    const tool = createMemoryProvenanceSignerPruneTool({
      pruner: f.pruner,
      auditLog: f.audit,
      isolationGuard: () => ({ allowed: true }),
    });
    const denied = await tool.handler({});
    expect(JSON.parse(denied.content[0]!.text)).toMatchObject({ denied: true });
    expect(await f.known.lookup(f.unusedA.did)).not.toBeNull();
    const allowed = await tool.handler({}, "agent:test", {
      approvalAuditId: "gate-tool-prune",
    });
    expect(JSON.parse(allowed.content[0]!.text)).toMatchObject({
      pruned: true,
      deleted: 2,
    });
  });

  it("permits zero-dependency bad-signer clear after the last reference and signer mapping are pruned", async () => {
    const f = await fixture();
    const fingerprint = memoryProvenancePublicKeyFingerprint(f.direct.publicKey);
    await f.bad.mark({
      signerDid: f.direct.did,
      publicKeySha256: fingerprint,
      reason: "last-reference integration",
      approvalAuditId: "gate-last-mark",
    }, f.audit);
    const relayedDocumentId = `mem.${OWNER}.${f.relayed.id}`;
    const relayedBefore = await f.storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(relayedDocumentId),
    );
    const relayedTierBefore = (await f.adapter.getPassageProvenance(f.relayed.id));
    await f.adapter.deletePassage(f.direct.id);
    const result = await f.pruner.prune({ approvalAuditId: "gate-last-prune" });
    expect(result.deleted.map((entry) => entry.signer_did)).toContain(f.direct.did);
    expect(await f.known.lookup(f.direct.did)).toBeNull();
    await expect(f.bad.clear({
      signerDid: f.direct.did,
      publicKeySha256: fingerprint,
      approvalAuditId: "gate-last-clear",
    }, f.audit)).resolves.toMatchObject({ complete: true, affected: 0 });
    expect(await f.storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(relayedDocumentId),
    )).toEqual(relayedBefore);
    const relayedTierAfter = await f.adapter.getPassageProvenance(f.relayed.id);
    expect(relayedTierAfter.status).toBe("verified");
    if (relayedTierBefore.status === "verified" && relayedTierAfter.status === "verified") {
      expect(relayedTierAfter.companion.admission.body.origin_trust_tier).toBe(
        relayedTierBefore.companion.admission.body.origin_trust_tier,
      );
    }
  });

  it("uses the same authenticated scan and deletion semantics on shipped filesystem storage", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-signer-prune-"));
    try {
      const storage = new FilesystemStorage(join(root, "state"));
      const local = testMemoryProvenanceDependencies(MASTER);
      const referenced = foreign(91, "fs-reference", "filesystem text", "foreign_direct");
      const unused = foreign(92, "fs-unused", "filesystem unused", "foreign_direct");
      const known = new KnownSignersStore(storage, MASTER, { partition: "memory_provenance" });
      await known.persistIfAbsent([
        { did: referenced.did, publicKey: referenced.publicKey },
        { did: unused.did, publicKey: unused.publicKey },
      ], "fs-fixture");
      const runtime = new Map([
        [referenced.did, referenced.publicKey],
        [unused.did, unused.publicKey],
      ]);
      const resolve = (identityId: string, did: string) =>
        runtime.get(did)?.slice() ?? local.resolveSignerPublicKey(identityId, did);
      const adapter = new SdwMemoryBackendAdapter({
        storage,
        masterKey: MASTER,
        fortressId: FORTRESS,
        ownerRef: OWNER,
        resolvePrimarySigningHandle: local.resolvePrimarySigningHandle,
        resolveSignerPublicKey: resolve,
        resolveMemoryIntegrityState: async () => "state_COMPLETE",
        now: () => NOW,
      });
      await adapter.insertPassage({
        passage_id: referenced.id,
        text: referenced.text,
        provenanceContext: exitV2ForeignImportIngress({
          origin: referenced.origin,
          originPublicKey: referenced.publicKey,
          trustTier: referenced.tier,
          transferLineageRef: "f".repeat(64),
        }),
      }, "user_content");
      const audit = new AuditLog(storage, MASTER);
      const pruner = new MemoryProvenanceSignerPruner({
        storage,
        masterKey: MASTER,
        fortressId: FORTRESS,
        knownSignersStore: known,
        resolveSignerPublicKey: resolve,
        forgetSigner: (did) => { runtime.delete(did); },
        auditLog: audit,
      });
      const result = await pruner.prune({ approvalAuditId: "gate-filesystem" });
      expect(result.deleted.map((entry) => entry.signer_did)).toEqual([unused.did]);
      expect(await known.lookup(referenced.did)).not.toBeNull();
      expect(await known.lookup(unused.did)).toBeNull();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

});
