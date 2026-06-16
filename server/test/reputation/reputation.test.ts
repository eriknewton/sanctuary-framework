/**
 * L4 Reputation Store Tests
 *
 * Verifies:
 * - Attestation recording with signatures
 * - Reputation query aggregation
 * - Export/import portability round-trip
 * - Signature verification on import
 * - Escrow creation and retrieval
 * - Principal guarantee creation with signed certificates
 * - All data encrypted at rest
 */

import { describe, it, expect } from "vitest";
import { ReputationStore } from "../../src/reputation/reputation-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  createIdentity,
  verify,
} from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { fromBase64url, stringToBytes } from "../../src/core/encoding.js";

function setupIdentity(masterKey: Uint8Array) {
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    "test-identity",
    encryptionKey,
    "recovery-key"
  );
  return { identity: storedIdentity, encryptionKey };
}

describe("L4 Reputation Store", () => {
  describe("record + query", () => {
    it("records an attestation and queries it back", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      const stored = await store.record(
        "txn-001",
        "did:key:counterparty123",
        { type: "transaction", result: "completed", metrics: { fulfillment_rate: 1.0 } },
        "commerce",
        identity,
        encryptionKey
      );

      expect(stored.attestation.attestation_id).toMatch(/^att-/);
      expect(stored.attestation.schema).toBe("sanctuary-interaction-v1");
      expect(stored.attestation.data.interaction_id).toBe("txn-001");
      expect(stored.attestation.data.outcome_result).toBe("completed");
      expect(stored.attestation.signature).toBeTruthy();

      // Query it
      const summary = await store.query({});
      expect(summary.total_interactions).toBe(1);
      expect(summary.completed).toBe(1);
      expect(summary.failed).toBe(0);
      expect(summary.contexts).toContain("commerce");
      expect(summary.aggregate_metrics.fulfillment_rate).toBeDefined();
      expect(summary.aggregate_metrics.fulfillment_rate!.mean).toBe(1.0);
    });

    it("filters queries by context", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "txn-001", "did:key:cp1",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey
      );
      await store.record(
        "txn-002", "did:key:cp2",
        { type: "service", result: "failed" },
        "support", identity, encryptionKey
      );

      const commerce = await store.query({ context: "commerce" });
      expect(commerce.total_interactions).toBe(1);
      expect(commerce.completed).toBe(1);

      const support = await store.query({ context: "support" });
      expect(support.total_interactions).toBe(1);
      expect(support.failed).toBe(1);
    });

    it("aggregates metrics correctly", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "t1", "did:key:cp",
        { type: "transaction", result: "completed", metrics: { score: 10 } },
        "test", identity, encryptionKey
      );
      await store.record(
        "t2", "did:key:cp",
        { type: "transaction", result: "completed", metrics: { score: 20 } },
        "test", identity, encryptionKey
      );
      await store.record(
        "t3", "did:key:cp",
        { type: "transaction", result: "completed", metrics: { score: 30 } },
        "test", identity, encryptionKey
      );

      const summary = await store.query({});
      const score = summary.aggregate_metrics.score!;
      expect(score.mean).toBe(20);
      expect(score.median).toBe(20);
      expect(score.min).toBe(10);
      expect(score.max).toBe(30);
      expect(score.count).toBe(3);
    });
  });

  describe("attestation signatures", () => {
    it("produces valid Ed25519 signatures", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      const stored = await store.record(
        "sig-test", "did:key:counterparty",
        { type: "transaction", result: "completed" },
        "test", identity, encryptionKey
      );

      // Verify the signature
      const dataBytes = stringToBytes(
        JSON.stringify(stored.attestation.data)
      );
      const sigBytes = fromBase64url(stored.attestation.signature);
      const pubKeyBytes = fromBase64url(identity.public_key);

      const valid = verify(dataBytes, sigBytes, pubKeyBytes);
      expect(valid).toBe(true);
    });
  });

  describe("export + import", () => {
    it("round-trips reputation through export/import", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      // Record some interactions
      await store.record(
        "rt-1", "did:key:cp1",
        { type: "transaction", result: "completed", metrics: { rate: 0.95 } },
        "commerce", identity, encryptionKey
      );
      await store.record(
        "rt-2", "did:key:cp2",
        { type: "service", result: "partial" },
        "support", identity, encryptionKey
      );

      // Export
      const bundle = await store.exportBundle(identity, encryptionKey);
      expect(bundle.version).toBe("SANCTUARY_REP_V1");
      expect(bundle.attestations).toHaveLength(2);
      expect(bundle.bundle_signature).toBeTruthy();

      // Import into fresh store
      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);

      const publicKeys = new Map<string, Uint8Array>();
      publicKeys.set(identity.did, fromBase64url(identity.public_key));

      const result = await store2.importBundle(bundle, true, publicKeys);
      expect(result.imported).toBe(2);
      expect(result.invalid).toBe(0);
      expect(result.contexts).toContain("commerce");
      expect(result.contexts).toContain("support");

      // Verify imported data is queryable
      const summary = await store2.query({});
      expect(summary.total_interactions).toBe(2);
    });

    it("rejects attestations with invalid signatures on import", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "bad-sig", "did:key:cp",
        { type: "transaction", result: "completed" },
        "test", identity, encryptionKey
      );

      const bundle = await store.exportBundle(identity, encryptionKey);

      // Tamper with the attestation signature
      bundle.attestations[0]!.signature = "AAAA_tampered_signature_AAAA";

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);

      const publicKeys = new Map<string, Uint8Array>();
      publicKeys.set(identity.did, fromBase64url(identity.public_key));

      const result = await store2.importBundle(bundle, true, publicKeys);
      expect(result.imported).toBe(0);
      expect(result.invalid).toBe(1);
    });

    it("accepts attestations without verification when verify_signatures=false", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "no-verify", "did:key:cp",
        { type: "transaction", result: "completed" },
        "test", identity, encryptionKey
      );

      const bundle = await store.exportBundle(identity, encryptionKey);
      bundle.attestations[0]!.signature = "AAAA_tampered_AAAA";

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);

      const result = await store2.importBundle(bundle, false, new Map());
      expect(result.imported).toBe(1);
      expect(result.invalid).toBe(0);
    });
  });

  describe("escrow", () => {
    it("creates and retrieves an escrow", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);

      const escrow = await store.createEscrow(
        "Buy 100 widgets at $5 each",
        "did:key:counterparty",
        3600, // 1 hour
        "did:key:creator",
        500
      );

      expect(escrow.escrow_id).toMatch(/^esc-/);
      expect(escrow.status).toBe("pending");
      expect(escrow.terms_hash).toBeTruthy();
      expect(escrow.collateral_amount).toBe(500);

      // Retrieve
      const retrieved = await store.getEscrow(escrow.escrow_id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.transaction_terms).toBe("Buy 100 widgets at $5 each");
      expect(retrieved!.counterparty_did).toBe("did:key:counterparty");

      // Verify expiration is in the future
      const expiresAt = new Date(retrieved!.expires_at).getTime();
      const createdAt = new Date(retrieved!.created_at).getTime();
      expect(expiresAt - createdAt).toBeGreaterThanOrEqual(3600 * 1000 - 100);
    });
  });

  describe("guarantee", () => {
    it("creates a signed guarantee certificate", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");

      const { storedIdentity: principal } = createIdentity(
        "principal",
        encryptionKey,
        "recovery-key"
      );
      const { storedIdentity: agent } = createIdentity(
        "agent",
        encryptionKey,
        "recovery-key"
      );

      const guarantee = await store.createGuarantee(
        principal,
        agent.did,
        "commerce transactions up to $10,000",
        86400, // 24 hours
        encryptionKey,
        10000
      );

      expect(guarantee.guarantee_id).toMatch(/^guar-/);
      expect(guarantee.principal_did).toBe(principal.did);
      expect(guarantee.agent_did).toBe(agent.did);
      expect(guarantee.scope).toBe("commerce transactions up to $10,000");
      expect(guarantee.certificate).toBeTruthy();
      expect(guarantee.max_liability).toBe(10000);
    });
  });

  describe("encryption at rest", () => {
    it("attestation plaintext never appears in raw storage", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      const uniqueMarker = "UNIQUE_INTERACTION_MARKER_XYZ789";

      await store.record(
        uniqueMarker, "did:key:counterparty",
        { type: "transaction", result: "completed" },
        "test", identity, encryptionKey
      );

      // Scan all stored bytes
      const entries = await storage.list("_reputation");
      for (const entry of entries) {
        const raw = await storage.read("_reputation", entry.key);
        if (!raw) continue;
        const rawStr = new TextDecoder().decode(raw);
        expect(rawStr).not.toContain(uniqueMarker);
      }
    });
  });

  // ─── v0.9.1: L4 evidence summary for SHR + dashboard ─────────────
  describe("summarizeForSHR", () => {
    it("returns zero counts on an empty store", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const summary = await store.summarizeForSHR();
      expect(summary.attestation_count).toBe(0);
      expect(summary.most_recent_attestation_at).toBeNull();
      expect(summary.dispute_count).toBe(0);
      expect(summary.context_breakdown).toEqual({});
      expect(summary.tier_distribution["verified-sovereign"]).toBe(0);
    });

    it("counts attestations by tier and context, tracks the most recent", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "a1", "did:key:cp",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey,
        undefined, "verified-sovereign"
      );
      await store.record(
        "a2", "did:key:cp",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey,
        undefined, "self-attested"
      );
      await store.record(
        "a3", "did:key:cp",
        { type: "transaction", result: "completed" },
        "negotiation", identity, encryptionKey,
        undefined, "unverified"
      );

      const summary = await store.summarizeForSHR();
      expect(summary.attestation_count).toBe(3);
      expect(summary.tier_distribution["verified-sovereign"]).toBe(1);
      expect(summary.tier_distribution["self-attested"]).toBe(1);
      expect(summary.tier_distribution["unverified"]).toBe(1);
      expect(summary.context_breakdown["commerce"]).toBe(2);
      expect(summary.context_breakdown["negotiation"]).toBe(1);
      expect(summary.most_recent_attestation_at).toBeTruthy();
    });

    it("counts disputes from outcome_result === 'disputed'", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "ok", "did:key:cp",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey
      );
      await store.record(
        "bad", "did:key:cp",
        { type: "dispute", result: "disputed" },
        "commerce", identity, encryptionKey
      );

      const summary = await store.summarizeForSHR();
      expect(summary.dispute_count).toBe(1);
      expect(summary.attestation_count).toBe(2);
    });

    it("filters by participant_did when provided", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "a1", "did:key:cp",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey
      );

      // Summary for a different DID should return zero counts
      const foreign = await store.summarizeForSHR("did:key:someone-else");
      expect(foreign.attestation_count).toBe(0);

      // Summary for the actual participant returns the record
      const self = await store.summarizeForSHR(identity.did);
      expect(self.attestation_count).toBe(1);
    });
  });
});
