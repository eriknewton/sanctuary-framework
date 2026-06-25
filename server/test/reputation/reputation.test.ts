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
import {
  REPUTATION_LEGACY_REJECT_MESSAGE,
  ReputationStore,
  buildReputationCompletenessManifest,
  reputationBundleSigningBytes,
  verifyReputationBundleCompleteness,
  type ReputationBundle,
} from "../../src/reputation/reputation-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  createIdentity,
  sign,
  verify,
} from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createReputationTools } from "../../src/reputation/tools.js";

function setupIdentity(masterKey: Uint8Array) {
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    "test-identity",
    encryptionKey,
    "recovery-key"
  );
  return { identity: storedIdentity, encryptionKey };
}

function parseToolResult(result: { content: Array<{ text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function publicKeysFor(identity: ReturnType<typeof setupIdentity>["identity"]) {
  const publicKeys = new Map<string, Uint8Array>();
  publicKeys.set(identity.did, fromBase64url(identity.public_key));
  return publicKeys;
}

function cloneBundle(bundle: ReputationBundle): ReputationBundle {
  return JSON.parse(JSON.stringify(bundle)) as ReputationBundle;
}

function stripManifest(bundle: ReputationBundle): ReputationBundle {
  const legacy = cloneBundle(bundle);
  delete legacy.completeness_manifest;
  return legacy;
}

function stripManifestAndResign(
  bundle: ReputationBundle,
  identity: ReturnType<typeof setupIdentity>["identity"],
  encryptionKey: Uint8Array
): ReputationBundle {
  const legacy = stripManifest(bundle);
  // Sign exactly like a genuine pre-manifest export / older exit artifact:
  // plain JSON.stringify over the four-field body (insertion order), with no
  // completeness_manifest key. This exercises the real legacy signing-bytes
  // verification path, not the manifest-inclusive canonical path.
  legacy.bundle_signature = toBase64url(
    sign(
      stringToBytes(
        JSON.stringify({
          version: legacy.version,
          attestations: legacy.attestations,
          exported_at: legacy.exported_at,
          exporter_did: legacy.exporter_did,
        })
      ),
      identity.encrypted_private_key,
      encryptionKey
    )
  );
  return legacy;
}

function resignAttestationAndBundle(
  bundle: ReputationBundle,
  identity: ReturnType<typeof setupIdentity>["identity"],
  encryptionKey: Uint8Array
): ReputationBundle {
  for (const attestation of bundle.attestations) {
    attestation.signature = toBase64url(
      sign(
        stringToBytes(JSON.stringify(attestation.data)),
        identity.encrypted_private_key,
        encryptionKey
      )
    );
  }
  bundle.completeness_manifest = buildReputationCompletenessManifest(
    bundle.exported_at,
    bundle.attestations
  );
  bundle.bundle_signature = toBase64url(
    sign(
      reputationBundleSigningBytes(bundle),
      identity.encrypted_private_key,
      encryptionKey
    )
  );
  return bundle;
}

describe("L4 Reputation Store", () => {
  describe("tool honesty", () => {
    it("describes exported-set completeness without claiming lifetime history", () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const identityManager = new IdentityManager(storage, masterKey);
      const auditLog = new AuditLog(storage, masterKey);
      const { tools } = createReputationTools(
        storage,
        masterKey,
        identityManager,
        auditLog
      );

      const exportTool = tools.find((tool) => tool.name === "reputation_export");
      const importTool = tools.find((tool) => tool.name === "reputation_import");
      expect(exportTool?.description).toContain(
        "It does not prove the export is the agent's complete lifetime history"
      );
      expect(importTool?.description).toContain(
        "it does not prove a complete lifetime history"
      );
      expect(exportTool?.description).not.toMatch(/complete track record/i);
      expect(importTool?.description).not.toMatch(/complete track record/i);
      expect(exportTool?.description).not.toMatch(/complete history of/i);
      expect(importTool?.description).not.toMatch(/complete history of/i);
    });
  });

  describe("record + query", () => {
    it("rejects Concordia-bridge raw-term metrics at the record boundary and reputation_record writes nothing", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await expect(
        store.record(
          "bridge-direct-bypass",
          "did:key:counterparty",
          {
            type: "negotiation",
            result: "completed",
            metrics: { price: 150 },
          },
          "concordia-bridge",
          identity,
          encryptionKey
        )
      ).rejects.toThrow(/price/);
      await expect(storage.list("_reputation")).resolves.toHaveLength(0);

      const identityManager = new IdentityManager(storage, masterKey);
      await identityManager.save(identity);
      await identityManager.setPrimary(identity.identity_id);
      const { tools } = createReputationTools(
        storage,
        masterKey,
        identityManager,
        new AuditLog(storage, masterKey)
      );
      const recordTool = tools.find((tool) => tool.name === "reputation_record");
      expect(recordTool).toBeDefined();

      const result = parseToolResult(
        await recordTool!.handler({
          interaction_id: "bridge-tool-bypass",
          counterparty_did: "did:key:counterparty",
          context: "concordia-bridge",
          outcome: {
            type: "negotiation",
            result: "completed",
            metrics: { price: 150 },
          },
        })
      );

      expect(result.error).toMatch(/only behavioral metrics are allowed/i);
      expect(result.error).toMatch(/price/);
      expect(result.attestation_id).toBeUndefined();
      await expect(storage.list("_reputation")).resolves.toHaveLength(0);
      await expect(store.query({ context: "concordia-bridge" })).resolves.toMatchObject({
        total_interactions: 0,
      });
    });

    it("rejects out-of-domain Concordia-bridge metrics at the record boundary and reputation_record writes nothing", async () => {
      const cases: Array<{
        metrics: Record<string, number>;
        message: RegExp;
        key: string;
      }> = [
        {
          metrics: { concession_magnitude: 150 },
          message: /0 to 1/i,
          key: "concession_magnitude",
        },
        {
          metrics: { response_time_ms: -1 },
          message: /non-negative/i,
          key: "response_time_ms",
        },
        {
          metrics: { reasoning_provided: 123 },
          message: /0 or 1/i,
          key: "reasoning_provided",
        },
      ];

      for (const scenario of cases) {
        const storage = new MemoryStorage();
        const masterKey = generateRandomKey();
        const store = new ReputationStore(storage, masterKey);
        const { identity, encryptionKey } = setupIdentity(masterKey);

        await expect(
          store.record(
            `bridge-direct-${scenario.key}`,
            "did:key:counterparty",
            {
              type: "negotiation",
              result: "completed",
              metrics: scenario.metrics,
            },
            "concordia-bridge",
            identity,
            encryptionKey
          )
        ).rejects.toThrow(scenario.message);
        await expect(storage.list("_reputation")).resolves.toHaveLength(0);

        const identityManager = new IdentityManager(storage, masterKey);
        await identityManager.save(identity);
        await identityManager.setPrimary(identity.identity_id);
        const { tools } = createReputationTools(
          storage,
          masterKey,
          identityManager,
          new AuditLog(storage, masterKey)
        );
        const recordTool = tools.find((tool) => tool.name === "reputation_record");
        expect(recordTool).toBeDefined();

        const result = parseToolResult(
          await recordTool!.handler({
            interaction_id: `bridge-tool-${scenario.key}`,
            counterparty_did: "did:key:counterparty",
            context: "concordia-bridge",
            outcome: {
              type: "negotiation",
              result: "completed",
              metrics: scenario.metrics,
            },
          })
        );

        expect(result.error).toMatch(scenario.message);
        expect(result.error).toMatch(scenario.key);
        expect(result.attestation_id).toBeUndefined();
        await expect(storage.list("_reputation")).resolves.toHaveLength(0);
      }
    });

    it("accepts in-domain Concordia-bridge metrics at the record boundary", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      const stored = await store.record(
        "bridge-in-domain",
        "did:key:counterparty",
        {
          type: "negotiation",
          result: "completed",
          metrics: {
            rounds: 3,
            negotiation_rounds: 4,
            offers_made: 2,
            response_time_ms: 0,
            concession_magnitude: 1,
            reasoning_provided: 1,
          },
        },
        "concordia-bridge",
        identity,
        encryptionKey
      );

      expect(stored.attestation.data.metrics).toEqual({
        rounds: 3,
        negotiation_rounds: 4,
        offers_made: 2,
        response_time_ms: 0,
        concession_magnitude: 1,
        reasoning_provided: 1,
      });
      const summary = await store.query({ context: "concordia-bridge" });
      expect(summary.total_interactions).toBe(1);
      expect(summary.aggregate_metrics.concession_magnitude.mean).toBe(1);
    });

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
      expect(bundle.completeness_manifest).toBeDefined();
      expect(bundle.completeness_manifest?.schema_version).toBe(1);
      expect(bundle.completeness_manifest?.format).toBe("SANCTUARY_REP_V1");
      expect(bundle.completeness_manifest?.exported_at).toBe(
        bundle.exported_at
      );
      expect(bundle.completeness_manifest?.total_attestation_count).toBe(2);
      expect(bundle.completeness_manifest?.context_count).toBe(2);
      expect(bundle.completeness_manifest?.contexts).toEqual([
        "commerce",
        "support",
      ]);
      expect(
        bundle.completeness_manifest?.context_attestations["commerce"]
          ?.attestation_count
      ).toBe(1);
      expect(
        bundle.completeness_manifest?.context_attestations["support"]
          ?.content_checksum_sha256
      ).toMatch(/^[A-Za-z0-9_-]{43}$/);

      // Import into fresh store
      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);

      const result = await store2.importBundle(
        bundle,
        true,
        publicKeysFor(identity)
      );
      expect(result.imported).toBe(2);
      expect(result.invalid).toBe(0);
      expect(result.completeness_verification).toBe("verified");
      expect(result.contexts).toContain("commerce");
      expect(result.contexts).toContain("support");

      // Verify imported data is queryable
      const summary = await store2.query({});
      expect(summary.total_interactions).toBe(2);
    });

    it("verifyBundle matches importBundle verification without writing", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "verify-only-1", "did:key:cp1",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey
      );

      const bundle = await store.exportBundle(identity, encryptionKey);
      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const publicKeys = publicKeysFor(identity);

      const verified = store2.verifyBundle(bundle, publicKeys);
      const standaloneCompleteness = verifyReputationBundleCompleteness(bundle);
      expect(verified).toEqual({
        invalid: 0,
        unverifiable: 0,
        contexts: ["commerce"],
        completeness_verification: "verified",
      });
      expect(standaloneCompleteness).toBe(
        verified.completeness_verification
      );
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);

      const imported = await store2.importBundle(bundle, true, publicKeys);
      expect(imported.invalid).toBe(verified.invalid);
      expect(imported.unverifiable).toBe(verified.unverifiable);
      expect(imported.contexts).toEqual(verified.contexts);
      expect(imported.completeness_verification).toBe(
        verified.completeness_verification
      );

      const tampered = cloneBundle(bundle);
      tampered.completeness_manifest!.total_attestation_count = 2;
      const storage3 = new MemoryStorage();
      const store3 = new ReputationStore(storage3, masterKey);
      expect(() => verifyReputationBundleCompleteness(tampered)).toThrow(
        "Reputation bundle completeness manifest does not match contents"
      );
      expect(() => store3.verifyBundle(tampered, publicKeys)).toThrow(
        "Reputation bundle completeness manifest does not match contents"
      );
      await expect(
        store3.importBundle(tampered, true, publicKeys)
      ).rejects.toThrow(
        "Reputation bundle completeness manifest does not match contents"
      );
      await expect(storage3.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects imported Concordia-bridge attestations with raw-term or out-of-domain metrics before any write", async () => {
      const cases: Array<{
        metrics: Record<string, number>;
        message: RegExp;
        key: string;
      }> = [
        {
          metrics: { price: 150 },
          message: /only behavioral metrics are allowed/i,
          key: "price",
        },
        {
          metrics: { concession_magnitude: 150 },
          message: /0 to 1/i,
          key: "concession_magnitude",
        },
      ];

      for (const scenario of cases) {
        const storage = new MemoryStorage();
        const masterKey = generateRandomKey();
        const store = new ReputationStore(storage, masterKey);
        const { identity, encryptionKey } = setupIdentity(masterKey);

        await store.record(
          `import-bridge-${scenario.key}`,
          "did:key:cp1",
          {
            type: "negotiation",
            result: "completed",
            metrics: { concession_magnitude: 0.25 },
          },
          "concordia-bridge",
          identity,
          encryptionKey
        );

        const tampered = cloneBundle(await store.exportBundle(identity, encryptionKey));
        tampered.attestations[0]!.data.metrics = scenario.metrics;
        resignAttestationAndBundle(tampered, identity, encryptionKey);

        const storage2 = new MemoryStorage();
        const store2 = new ReputationStore(storage2, masterKey);
        const publicKeys = publicKeysFor(identity);

        expect(() => store2.verifyBundle(tampered, publicKeys)).toThrow(
          scenario.message
        );
        expect(() => store2.verifyBundle(tampered, publicKeys)).toThrow(
          scenario.key
        );
        await expect(
          store2.importBundle(tampered, true, publicKeys)
        ).rejects.toThrow(scenario.message);
        await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
      }
    });

    it("imports non-bridge-context attestations with domain-specific metrics unchanged", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "import-non-bridge-price",
        "did:key:cp1",
        {
          type: "transaction",
          result: "completed",
          metrics: { price: 150 },
        },
        "commerce",
        identity,
        encryptionKey
      );

      const bundle = await store.exportBundle(identity, encryptionKey);
      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const result = await store2.importBundle(bundle, true, publicKeysFor(identity));

      expect(result.imported).toBe(1);
      expect(result.invalid).toBe(0);
      const summary = await store2.query({ context: "commerce" });
      expect(summary.total_interactions).toBe(1);
      expect(summary.aggregate_metrics.price.mean).toBe(150);
    });

    it("rejects a dropped attestation before any import write", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "drop-1", "did:key:cp1",
        { type: "transaction", result: "completed" },
        "test", identity, encryptionKey
      );
      await store.record(
        "drop-2", "did:key:cp2",
        { type: "transaction", result: "completed" },
        "test", identity, encryptionKey
      );

      const bundle = await store.exportBundle(identity, encryptionKey);
      const tampered = cloneBundle(bundle);
      tampered.attestations.pop();

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);

      await expect(
        store2.importBundle(tampered, true, publicKeysFor(identity))
      ).rejects.toThrow(
        "Reputation bundle completeness manifest does not match contents"
      );
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects a wrong context count before any import write", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "count-1", "did:key:cp",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey
      );

      const bundle = await store.exportBundle(identity, encryptionKey);
      const tampered = cloneBundle(bundle);
      tampered.completeness_manifest!.context_attestations[
        "commerce"
      ]!.attestation_count = 2;
      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);

      await expect(
        store2.importBundle(tampered, true, publicKeysFor(identity))
      ).rejects.toThrow(
        "Reputation bundle completeness manifest does not match contents"
      );
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects an altered context checksum before any import write", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "checksum-1", "did:key:cp",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey
      );

      const bundle = await store.exportBundle(identity, encryptionKey);
      const tampered = cloneBundle(bundle);
      tampered.completeness_manifest!.context_attestations[
        "commerce"
      ]!.content_checksum_sha256 = "0".repeat(64);

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);

      await expect(
        store2.importBundle(tampered, true, publicKeysFor(identity))
      ).rejects.toThrow(
        "Reputation bundle completeness manifest does not match contents"
      );
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects per-attestation signature failures before any import write even when verifySignatures is false", async () => {
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
      const tampered = cloneBundle(bundle);
      tampered.attestations[0]!.signature = "AAAA_tampered_signature_AAAA";
      tampered.completeness_manifest = buildReputationCompletenessManifest(
        tampered.exported_at,
        tampered.attestations
      );
      tampered.bundle_signature = toBase64url(
        sign(
          reputationBundleSigningBytes(tampered),
          identity.encrypted_private_key,
          encryptionKey
        )
      );

      for (const verifySignatures of [true, false]) {
        const storage2 = new MemoryStorage();
        const store2 = new ReputationStore(storage2, masterKey);

        await expect(
          store2.importBundle(tampered, verifySignatures, publicKeysFor(identity))
        ).rejects.toThrow(
          "Reputation bundle contains attestations with invalid or unverifiable signatures"
        );
        await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
      }
    });

    it("rejects manifestless legacy bundles unless explicitly opted in", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "legacy-1", "did:key:cp",
        { type: "transaction", result: "completed" },
        "test", identity, encryptionKey
      );

      const legacyBundle = stripManifestAndResign(
        await store.exportBundle(identity, encryptionKey),
        identity,
        encryptionKey
      );
      const badSignatureLegacyBundle = cloneBundle(legacyBundle);
      badSignatureLegacyBundle.bundle_signature = toBase64url(new Uint8Array(64));

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);

      await expect(
        store2.importBundle(legacyBundle, true, publicKeysFor(identity))
      ).rejects.toThrow(REPUTATION_LEGACY_REJECT_MESSAGE);
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);

      const storageWithBadSignature = new MemoryStorage();
      const storeWithBadSignature = new ReputationStore(
        storageWithBadSignature,
        masterKey
      );
      await expect(
        storeWithBadSignature.importBundle(
          badSignatureLegacyBundle,
          true,
          publicKeysFor(identity),
          { allowUnverifiedLegacy: true }
        )
      ).rejects.toThrow("Reputation bundle signature verification failed");
      await expect(
        storageWithBadSignature.list("_reputation")
      ).resolves.toHaveLength(0);

      const result = await store2.importBundle(
        legacyBundle,
        true,
        publicKeysFor(identity),
        { allowUnverifiedLegacy: true }
      );
      expect(
        verifyReputationBundleCompleteness(legacyBundle, {
          allowUnverifiedLegacy: true,
        })
      ).toBe(result.completeness_verification);
      expect(result.imported).toBe(1);
      expect(result.invalid).toBe(0);
      expect(result.unverifiable).toBe(0);
      expect(result.completeness_verification).toBe(
        "unverified-completeness-legacy-bundle"
      );
      expect(result.completeness_verification).not.toBe("verified");
    });

    it("rejects newer manifest schema versions fail closed", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "newer-1", "did:key:cp",
        { type: "transaction", result: "completed" },
        "test", identity, encryptionKey
      );

      const bundle = await store.exportBundle(identity, encryptionKey);
      const tampered = cloneBundle(bundle);
      tampered.completeness_manifest!.schema_version = 2 as 1;

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);

      await expect(
        store2.importBundle(tampered, true, publicKeysFor(identity))
      ).rejects.toThrow(
        "Reputation bundle completeness schema version is newer than this build supports"
      );
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
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
