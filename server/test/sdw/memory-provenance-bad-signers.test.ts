import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";

import { publicKeyToDid } from "../../src/core/identity.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import {
  MemoryProvenanceBadSignerStore,
  MEMORY_PROVENANCE_BAD_SIGNER_MARK_AUDIT,
  MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE,
  memoryProvenancePublicKeyFingerprint,
} from "../../src/sdw/memory-provenance-bad-signers.js";
import { clusterMemoryProvenanceForContext, isMemoryProvenanceOutboundSyncEligible } from "../../src/sdw/memory-provenance-routing.js";
import { signMemoryOrigin } from "../../src/sdw/memory-provenance-contract.js";
import { exitV2ForeignImportIngress } from "../../src/sdw/memory-provenance-ingress.js";
import { passageContentHash } from "../../src/sdw/write-gate.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { testMemoryProvenanceDependencies } from "./test-memory-backend.js";
import { createMemoryProvenanceBadSignerTools } from "../../src/sdw/memory-provenance-bad-signer-tools.js";

const MASTER = new Uint8Array(32).fill(41);
const NOW = "2026-08-24T22:00:00.000Z";

class OrderedStorage extends MemoryStorage {
  readonly writes: string[] = [];
  failBadSignerWrite = false;
  failBadSignerDeleteAfterRemoval = false;
  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.writes.push(namespace);
    if (namespace === MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE && this.failBadSignerWrite) {
      this.failBadSignerWrite = false;
      throw new Error("injected bad-signer state write failure");
    }
    return super.write(namespace, key, data);
  }
  override async delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    const deleted = await super.delete(namespace, key, secureOverwrite);
    if (namespace === MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE &&
        this.failBadSignerDeleteAfterRemoval) {
      this.failBadSignerDeleteAfterRemoval = false;
      throw new Error("injected post-removal failure");
    }
    return deleted;
  }
}

function foreign(seedByte: number, id: string, text: string, tier: "foreign_direct" | "foreign_relayed") {
  const seed = new Uint8Array(32).fill(seedByte);
  const publicKey = ed25519.getPublicKey(seed);
  const did = publicKeyToDid(publicKey);
  const signed = signMemoryOrigin({
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
  if (!signed.ok) throw new Error(signed.error.message);
  return { id, did, publicKey, text, tier, origin: signed.value };
}

async function fixture() {
  const storage = new OrderedStorage();
  const local = testMemoryProvenanceDependencies(MASTER);
  const direct = foreign(71, "direct-id", "direct secret text", "foreign_direct");
  const relayed = foreign(72, "relay-id", "relayed secret text", "foreign_relayed");
  const keys = new Map([[direct.did, direct.publicKey], [relayed.did, relayed.publicKey]]);
  let adapter!: SdwMemoryBackendAdapter;
  const store = new MemoryProvenanceBadSignerStore({
    storage,
    masterKey: MASTER,
    fortressId: "fortress-local",
    resolveSignerPublicKey: (did) => keys.get(did)?.slice(),
    isLocallyRootedSigner: () => false,
    scanForeignDependencies: (did, fingerprint) =>
      adapter.scanForeignSignerDependencies(did, fingerprint),
    now: () => NOW,
  });
  adapter = new SdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER,
    fortressId: "fortress-local",
    ownerRef: "fleet-self",
    maxChunkChars: 100,
    now: () => NOW,
    resolvePrimarySigningHandle: local.resolvePrimarySigningHandle,
    resolveSignerPublicKey: (identityId, did) =>
      keys.get(did)?.slice() ?? local.resolveSignerPublicKey(identityId, did),
    resolveMemoryIntegrityState: async () => "state_COMPLETE",
    badSignerAuthority: store,
  });
  for (const item of [direct, relayed]) {
    await adapter.insertPassage({
      passage_id: item.id,
      text: item.text,
      provenanceContext: exitV2ForeignImportIngress({
        origin: item.origin,
        originPublicKey: item.publicKey,
        trustTier: item.tier,
        transferLineageRef: `${item.id[0]}`.repeat(64),
      }),
    }, "user_content");
  }
  return { storage, adapter, store, direct, relayed, keys, local };
}

describe("C4 foreign bad-signer quarantine", () => {
  it.each(["direct", "relayed"] as const)(
    "quarantines %s foreign records across reads, search, list, export eligibility and clustering",
    async (which) => {
      const f = await fixture();
      const item = f[which];
      const before = await f.adapter.getPassageProvenance(item.id);
      expect(before.status).toBe("verified");
      if (before.status !== "verified") return;
      const audit = new AuditLog(f.storage, MASTER);
      f.storage.writes.length = 0;
      await f.store.mark({
        signerDid: item.did,
        publicKeySha256: memoryProvenancePublicKeyFingerprint(item.publicKey),
        reason: "operator-confirmed-compromise",
        approvalAuditId: "gate-approval-1234",
      }, audit);
      expect(f.storage.writes.indexOf("_audit")).toBeLessThan(
        f.storage.writes.indexOf(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE),
      );
      await expect(f.adapter.getPassageProvenance(item.id)).resolves.toMatchObject({
        status: "quarantined", reason: "foreign_bad_signer",
      });
      await expect(f.adapter.getPassage(item.id)).rejects.toThrow(/quarantined/);
      expect(await f.adapter.searchPassages({ text: "secret" })).not.toEqual(
        expect.arrayContaining([expect.objectContaining({ passage: expect.objectContaining({ passage_id: item.id }) })]),
      );
      expect(await f.adapter.listPassages()).not.toEqual(
        expect.arrayContaining([expect.objectContaining({ passage_id: item.id })]),
      );
      expect(isMemoryProvenanceOutboundSyncEligible({
        state: "state_COMPLETE",
        companionVerified: true,
        companion: before.companion,
        quarantined: true,
      })).toBe(false);
      expect(clusterMemoryProvenanceForContext([
        { companion: before.companion, quarantined: true },
      ])).toMatchObject({ quarantinedVectorCount: 1, largestClusterSize: 1 });
      const events = await audit.query({ operation_type: MEMORY_PROVENANCE_BAD_SIGNER_MARK_AUDIT });
      expect(events.entries).toHaveLength(1);
    },
  );

  it("survives restart, rejects DID/fingerprint conflicts, and clear preserves origin bytes and tier", async () => {
    const f = await fixture();
    const fingerprint = memoryProvenancePublicKeyFingerprint(f.direct.publicKey);
    const before = await f.adapter.getPassageProvenance(f.direct.id);
    if (before.status !== "verified") throw new Error("fixture provenance did not verify");
    const audit = new AuditLog(f.storage, MASTER);
    await f.store.mark({ signerDid: f.direct.did, publicKeySha256: fingerprint,
      reason: "compromise", approvalAuditId: "gate-approval-mark" }, audit);
    const restartedStore = new MemoryProvenanceBadSignerStore({
      storage: f.storage, masterKey: MASTER, fortressId: "fortress-local",
      resolveSignerPublicKey: (did) => f.keys.get(did)?.slice(),
      isLocallyRootedSigner: () => false,
      scanForeignDependencies: (did, fp) => f.adapter.scanForeignSignerDependencies(did, fp),
      now: () => NOW,
    });
    expect(await restartedStore.isMarked(f.direct.did, f.direct.publicKey)).toBe(true);
    await expect(f.store.mark({ signerDid: f.direct.did, publicKeySha256: "0".repeat(64),
      reason: "collision", approvalAuditId: "gate-approval-collision" }, audit)).rejects.toThrow(/fingerprint/);
    const scan = await restartedStore.clear({ signerDid: f.direct.did,
      publicKeySha256: fingerprint, approvalAuditId: "gate-approval-clear" }, audit);
    expect(scan).toMatchObject({ complete: true, affected: 1 });
    const after = await f.adapter.getPassageProvenance(f.direct.id);
    expect(after.status).toBe("verified");
    if (after.status !== "verified") return;
    expect(after.companion.origin).toEqual(before.companion.origin);
    expect(after.companion.admission.body.origin_trust_tier).toBe("foreign_direct");
  });

  it("leaves eligibility unchanged on audit/state failures and refuses incomplete clear scans", async () => {
    const f = await fixture();
    const fingerprint = memoryProvenancePublicKeyFingerprint(f.direct.publicKey);
    const audit = new AuditLog(f.storage, MASTER);
    f.storage.failBadSignerWrite = true;
    await expect(f.store.mark({ signerDid: f.direct.did, publicKeySha256: fingerprint,
      reason: "compromise", approvalAuditId: "gate-approval-fail" }, audit)).rejects.toThrow(/injected/);
    expect((await f.adapter.getPassageProvenance(f.direct.id)).status).toBe("verified");
    await f.store.mark({ signerDid: f.direct.did, publicKeySha256: fingerprint,
      reason: "compromise", approvalAuditId: "gate-approval-mark" }, audit);
    const [markEntry] = await f.storage.list(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE);
    const exactPreState = await f.storage.read(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE, markEntry!.key);
    f.storage.failBadSignerDeleteAfterRemoval = true;
    await expect(f.store.clear({ signerDid: f.direct.did, publicKeySha256: fingerprint,
      approvalAuditId: "gate-approval-clear-fail" }, audit)).rejects.toThrow(/injected/);
    expect(await f.storage.read(MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE, markEntry!.key))
      .toEqual(exactPreState);
    expect(await f.store.isMarked(f.direct.did, f.direct.publicKey)).toBe(true);
    const incomplete = new MemoryProvenanceBadSignerStore({
      storage: f.storage, masterKey: MASTER, fortressId: "fortress-local",
      resolveSignerPublicKey: (did) => f.keys.get(did)?.slice(),
      isLocallyRootedSigner: () => false,
      scanForeignDependencies: async () => ({ complete: false, scanned: 2_000, affected: 1 }),
    });
    await expect(incomplete.clear({ signerDid: f.direct.did, publicKeySha256: fingerprint,
      approvalAuditId: "gate-approval-clear" }, audit)).rejects.toThrow(/incomplete/);
    expect(await f.store.isMarked(f.direct.did, f.direct.publicKey)).toBe(true);
  });

  it("bounds attacker strings before scans and refuses local or unknown mappings", async () => {
    const f = await fixture();
    const audit = new AuditLog(f.storage, MASTER);
    await expect(f.store.mark({ signerDid: f.direct.did,
      publicKeySha256: memoryProvenancePublicKeyFingerprint(f.direct.publicKey),
      reason: "x".repeat(257), approvalAuditId: "gate-approval-bound" }, audit)).rejects.toThrow(/reason/);
    await expect(f.store.mark({ signerDid: publicKeyToDid(new Uint8Array(32).fill(99)),
      publicKeySha256: "0".repeat(64), reason: "unknown", approvalAuditId: "gate-approval-unknown" }, audit)).rejects.toThrow(/unknown/);
  });

  it("binds the real operator tools to a gate-minted approval id", async () => {
    const f = await fixture();
    const audit = new AuditLog(f.storage, MASTER);
    const [mark] = createMemoryProvenanceBadSignerTools({
      store: f.store,
      auditLog: audit,
      isolationGuard: () => ({ allowed: true }),
    });
    const args = {
      signer_did: f.direct.did,
      public_key_sha256: memoryProvenancePublicKeyFingerprint(f.direct.publicKey),
      reason: "compromise",
    };
    expect(mark).toBeDefined();
    const denied = await mark!.handler(args);
    expect(JSON.parse(denied.content[0]!.text)).toMatchObject({ denied: true });
    expect(await f.store.isMarked(f.direct.did, f.direct.publicKey)).toBe(false);
    const allowed = await mark!.handler(args, "agent:test", {
      approvalAuditId: "gate-approval-tool",
    });
    expect(JSON.parse(allowed.content[0]!.text)).toMatchObject({ marked: true });
    const events = await audit.query({ operation_type: MEMORY_PROVENANCE_BAD_SIGNER_MARK_AUDIT });
    expect(events.entries[0]?.details).toMatchObject({ approval_audit_id: "gate-approval-tool" });
  });

  it("clears a stranded exact mark after a complete zero-dependency scan when its mapping was safely pruned", async () => {
    const f = await fixture();
    const fingerprint = memoryProvenancePublicKeyFingerprint(f.direct.publicKey);
    const audit = new AuditLog(f.storage, MASTER);
    await f.store.mark({ signerDid: f.direct.did, publicKeySha256: fingerprint,
      reason: "compromise", approvalAuditId: "gate-approval-mark" }, audit);
    await f.adapter.deletePassage(f.direct.id);
    const afterPrune = new MemoryProvenanceBadSignerStore({
      storage: f.storage,
      masterKey: MASTER,
      fortressId: "fortress-local",
      resolveSignerPublicKey: () => undefined,
      isLocallyRootedSigner: () => false,
      scanForeignDependencies: async () => ({ complete: true, scanned: 1, affected: 0 }),
    });
    await expect(afterPrune.clear({ signerDid: f.direct.did, publicKeySha256: fingerprint,
      approvalAuditId: "gate-approval-clear" }, audit)).resolves.toMatchObject({ affected: 0 });
    expect(await afterPrune.isMarked(f.direct.did, f.direct.publicKey)).toBe(false);
  });
});
