// fail-before-exempt: adaptation-only in this PR — removes references to the deleted counterparty_confirmed field from StoredAttestation fixtures; the behavior change (the flag is now absent from the reputation_record response) is proven by test/reputation/weight-by-signer.test.ts, which does fail against pre-fix source.
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
  trustedSovereigntyTier,
  verifyReputationBundleCompleteness,
  type Attestation,
  type ReputationBundle,
  type StoredAttestation,
} from "../../src/reputation/reputation-store.js";
import type { SovereigntyTier } from "../../src/reputation/tiers.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
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
import { encrypt } from "../../src/core/encryption.js";
import { hash } from "../../src/core/hashing.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createReputationTools } from "../../src/reputation/tools.js";
import {
  BRIDGE_METRIC_POLICY,
  bridgeCountBucket,
} from "../../src/reputation/bridge-metrics.js";
import { createBridgeCommitment } from "../../src/bridge/bridge.js";
import type { BridgeCommitment, ConcordiaOutcome } from "../../src/bridge/types.js";

function setupIdentity(
  masterKey: Uint8Array,
  label = "test-identity"
) {
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    label,
    encryptionKey,
    "recovery-key"
  );
  return { identity: storedIdentity, encryptionKey };
}

function parseToolResult(result: { content: Array<{ text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function publicKeysFor(
  ...identities: Array<ReturnType<typeof setupIdentity>["identity"]>
) {
  const publicKeys = new Map<string, Uint8Array>();
  for (const identity of identities) {
    publicKeys.set(identity.did, fromBase64url(identity.public_key));
  }
  return publicKeys;
}

function cloneBundle(bundle: ReputationBundle): ReputationBundle {
  return JSON.parse(JSON.stringify(bundle)) as ReputationBundle;
}

/**
 * Observe the reputation_query_weighted MCP tool output over the same
 * storage + masterKey a ReputationStore persists to. The tool builds its own
 * store over that storage, so it reads exactly the records under test. This is
 * the end-to-end scoring surface an agent actually calls, used to prove the
 * tier clamp is enforced at the loadAllForTierScoring boundary rather than only
 * when a caller remembers to call trustedSovereigntyTier.
 */
async function queryWeighted(
  store: ReputationStore,
  masterKey: Uint8Array,
  metric: string
): Promise<{
  weighted_score: number;
  tier_distribution: Record<SovereigntyTier, number>;
}> {
  // The store already holds the storage; reuse it so the tool sees the same
  // persisted _reputation records.
  const storage = (store as unknown as { storage: StorageBackend }).storage;
  const identityManager = new IdentityManager(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const { tools } = createReputationTools(
    storage,
    masterKey,
    identityManager,
    auditLog
  );
  const tool = tools.find((t) => t.name === "reputation_query_weighted");
  if (!tool) throw new Error("reputation_query_weighted tool not found");
  const result = await tool.handler({ metric });
  return JSON.parse(result.content[0]!.text) as {
    weighted_score: number;
    tier_distribution: Record<SovereigntyTier, number>;
  };
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

async function writeMatchingBridgeCommitment(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identity: ReturnType<typeof setupIdentity>["identity"],
  encryptionKey: Uint8Array,
  options: {
    interactionId: string;
    counterpartyDid: string;
    rounds?: number;
  }
): Promise<{
  commitment: BridgeCommitment;
  outcome: ConcordiaOutcome;
}> {
  await writeStoredIdentityForBridgeVerification(storage, masterKey, identity);
  const terms = { scope: "privacy" };
  const outcome: ConcordiaOutcome = {
    session_id: options.interactionId,
    protocol_version: "concordia-v1",
    proposer_did: identity.did,
    acceptor_did: options.counterpartyDid,
    terms,
    terms_hash: toBase64url(hash(stringToBytes(JSON.stringify(terms)))),
    rounds: options.rounds ?? 3,
    accepted_at: "2026-06-25T12:00:00.000Z",
  };
  const commitment = createBridgeCommitment(
    outcome,
    identity,
    encryptionKey
  );
  await writeBridgeCommitmentRecord(storage, masterKey, commitment, outcome);
  return { commitment, outcome };
}

async function writeStoredIdentityForBridgeVerification(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identity: ReturnType<typeof setupIdentity>["identity"]
): Promise<void> {
  const identityEncryptionKey = derivePurposeKey(
    masterKey,
    "identity-encryption"
  );
  const encrypted = encrypt(
    stringToBytes(JSON.stringify(identity)),
    identityEncryptionKey
  );
  await storage.write(
    "_identities",
    identity.identity_id,
    stringToBytes(JSON.stringify(encrypted))
  );
}

async function writeBridgeCommitmentRecord(
  storage: StorageBackend,
  masterKey: Uint8Array,
  commitment: BridgeCommitment,
  outcome: ConcordiaOutcome
): Promise<void> {
  const bridgeEncryptionKey = derivePurposeKey(masterKey, "bridge-commitments");
  const encrypted = encrypt(
    stringToBytes(JSON.stringify({ commitment, outcome })),
    bridgeEncryptionKey
  );
  await storage.write(
    "_bridge",
    commitment.bridge_commitment_id,
    stringToBytes(JSON.stringify(encrypted))
  );
}

async function writeBridgeAttestationRecord(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identity: ReturnType<typeof setupIdentity>["identity"],
  encryptionKey: Uint8Array,
  options: {
    interactionId: string;
    counterpartyDid: string;
    metrics: Record<string, number>;
    metricPolicy?: string;
  }
): Promise<StoredAttestation> {
  const now = new Date().toISOString();
  const data: Attestation["data"] = {
    interaction_id: options.interactionId,
    participant_did: identity.did,
    counterparty_did: options.counterpartyDid,
    outcome_type: "negotiation",
    outcome_result: "completed",
    metrics: options.metrics,
    ...(options.metricPolicy !== undefined
      ? { metric_policy: options.metricPolicy }
      : {}),
    context: "concordia-bridge",
    timestamp: now,
  };
  const attestationId = `att-test-${options.interactionId}`;
  const attestation: Attestation = {
    attestation_id: attestationId,
    schema: "sanctuary-interaction-v1",
    data,
    signature: toBase64url(
      sign(
        stringToBytes(JSON.stringify(data)),
        identity.encrypted_private_key,
        encryptionKey
      )
    ),
    signer: identity.did,
  };
  const stored: StoredAttestation = {
    attestation,
    recorded_at: now,
  };
  const reputationKey = derivePurposeKey(masterKey, "l4-reputation");
  const encrypted = encrypt(
    stringToBytes(JSON.stringify(stored)),
    reputationKey
  );
  await storage.write(
    "_reputation",
    attestationId,
    stringToBytes(JSON.stringify(encrypted))
  );
  return stored;
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
    it("rejects new Concordia-bridge records without the bridge metric policy", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await expect(
        store.record(
          "bridge-missing-policy",
          "did:key:counterparty",
          {
            type: "negotiation",
            result: "completed",
            metrics: { negotiation_round_bucket: 1 },
          },
          "concordia-bridge",
          identity,
          encryptionKey
        )
      ).rejects.toThrow(/metric_policy/);
      await expect(storage.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects Concordia-bridge raw-term metrics at the record boundary and writes nothing", async () => {
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
            metric_policy: BRIDGE_METRIC_POLICY,
          },
          "concordia-bridge",
          identity,
          encryptionKey
        )
      ).rejects.toThrow(/price/);
      await expect(storage.list("_reputation")).resolves.toHaveLength(0);
    });

    it("reputation_record refuses Concordia-bridge context even with policy-rated buckets", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const { identity } = setupIdentity(masterKey);

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
            metrics: {
              negotiation_round_bucket: 1,
              declared_concession_bucket: 3,
            },
            metric_policy: BRIDGE_METRIC_POLICY,
          },
        })
      );

      expect(result.error).toMatch(/bridge_attest/);
      expect(result.attestation_id).toBeUndefined();
      await expect(storage.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects out-of-domain Concordia-bridge metrics at the record boundary and writes nothing", async () => {
      const cases: Array<{
        metrics: Record<string, number>;
        message: RegExp;
        key: string;
      }> = [
        {
          metrics: {
            negotiation_round_bucket: 1,
            declared_concession_bucket: 150,
          },
          message: /0 to 10/i,
          key: "declared_concession_bucket",
        },
        {
          metrics: {
            negotiation_round_bucket: 1,
            declared_response_time_bucket: -1,
          },
          message: /0 to 5/i,
          key: "declared_response_time_bucket",
        },
        {
          metrics: {
            negotiation_round_bucket: 1,
            declared_reasoning_provided: 123,
          },
          message: /0 or 1/i,
          key: "declared_reasoning_provided",
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
              metric_policy: BRIDGE_METRIC_POLICY,
            },
            "concordia-bridge",
            identity,
            encryptionKey
          )
        ).rejects.toThrow(scenario.message);
        await expect(storage.list("_reputation")).resolves.toHaveLength(0);
      }
    });

    it("rejects policy-rated Concordia-bridge metrics without local bridge commitment provenance", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await expect(
        store.record(
          "bridge-no-local-commitment",
          "did:key:counterparty",
          {
            type: "negotiation",
            result: "completed",
            metrics: {
              negotiation_round_bucket: 1,
              declared_offers_made_bucket: 2,
              declared_response_time_bucket: 0,
              declared_concession_bucket: 10,
              declared_reasoning_provided: 1,
            },
            metric_policy: BRIDGE_METRIC_POLICY,
          },
          "concordia-bridge",
          identity,
          encryptionKey
        )
      ).rejects.toThrow(/matching local bridge commitment/);
      await expect(storage.list("_reputation")).resolves.toHaveLength(0);
    });

    it("accepts policy-rated Concordia-bridge metrics when local bridge commitment provenance exists", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);
      const interactionId = "bridge-in-domain";
      const counterpartyDid = "did:key:counterparty";

      await writeMatchingBridgeCommitment(storage, masterKey, identity, encryptionKey, {
        interactionId,
        counterpartyDid,
      });

      const stored = await store.record(
        interactionId,
        counterpartyDid,
        {
          type: "negotiation",
          result: "completed",
          metrics: {
            negotiation_round_bucket: 1,
            declared_offers_made_bucket: 2,
            declared_response_time_bucket: 0,
            declared_concession_bucket: 10,
            declared_reasoning_provided: 1,
          },
          metric_policy: BRIDGE_METRIC_POLICY,
        },
        "concordia-bridge",
        identity,
        encryptionKey
      );

      expect(stored.attestation.data.metrics).toEqual({
        negotiation_round_bucket: 1,
        declared_offers_made_bucket: 2,
        declared_response_time_bucket: 0,
        declared_concession_bucket: 10,
        declared_reasoning_provided: 1,
      });
      expect(stored.attestation.data.metric_policy).toBe(BRIDGE_METRIC_POLICY);
      const summary = await store.query({ context: "concordia-bridge" });
      expect(summary.total_interactions).toBe(1);
      expect(summary.aggregate_metrics.declared_concession_bucket.mean).toBe(10);
    });

    it("rejects policy-rated Concordia-bridge metrics when local bridge commitment verification fails", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);
      const interactionId = "bridge-invalid-signature";
      const counterpartyDid = "did:key:counterparty";

      const { commitment, outcome } = await writeMatchingBridgeCommitment(
        storage,
        masterKey,
        identity,
        encryptionKey,
        {
          interactionId,
          counterpartyDid,
          rounds: 3,
        }
      );
      await writeBridgeCommitmentRecord(
        storage,
        masterKey,
        {
          ...commitment,
          signature: toBase64url(new Uint8Array(64)),
        },
        outcome
      );

      await expect(
        store.record(
          interactionId,
          counterpartyDid,
          {
            type: "negotiation",
            result: "completed",
            metrics: {
              negotiation_round_bucket: bridgeCountBucket(outcome.rounds),
              declared_offers_made_bucket: 2,
            },
            metric_policy: BRIDGE_METRIC_POLICY,
          },
          "concordia-bridge",
          identity,
          encryptionKey
        )
      ).rejects.toThrow(/matching local bridge commitment/);
      await expect(storage.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects policy-rated Concordia-bridge metrics when the bucket does not match the committed outcome", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);
      const interactionId = "bridge-bucket-mismatch";
      const counterpartyDid = "did:key:counterparty";

      const { outcome } = await writeMatchingBridgeCommitment(
        storage,
        masterKey,
        identity,
        encryptionKey,
        {
          interactionId,
          counterpartyDid,
          rounds: 9,
        }
      );
      expect(bridgeCountBucket(outcome.rounds)).toBe(3);

      await expect(
        store.record(
          interactionId,
          counterpartyDid,
          {
            type: "negotiation",
            result: "completed",
            metrics: {
              negotiation_round_bucket: 1,
              declared_offers_made_bucket: 2,
            },
            metric_policy: BRIDGE_METRIC_POLICY,
          },
          "concordia-bridge",
          identity,
          encryptionKey
        )
      ).rejects.toThrow(/matching local bridge commitment/);
      await expect(storage.list("_reputation")).resolves.toHaveLength(0);
    });

    it("reputation query tools label policy-rated bridge metrics", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);
      const interactionId = "bridge-policy-weighted";
      const counterpartyDid = "did:key:counterparty";

      await writeMatchingBridgeCommitment(storage, masterKey, identity, encryptionKey, {
        interactionId,
        counterpartyDid,
      });
      await store.record(
        interactionId,
        counterpartyDid,
        {
          type: "negotiation",
          result: "completed",
          metrics: {
            negotiation_round_bucket: 1,
            declared_concession_bucket: 3,
          },
          metric_policy: BRIDGE_METRIC_POLICY,
        },
        "concordia-bridge",
        identity,
        encryptionKey
      );

      const identityManager = new IdentityManager(storage, masterKey);
      await identityManager.save(identity);
      await identityManager.setPrimary(identity.identity_id);
      const { tools } = createReputationTools(
        storage,
        masterKey,
        identityManager,
        new AuditLog(storage, masterKey)
      );
      const queryTool = tools.find((tool) => tool.name === "reputation_query");
      const weightedTool = tools.find((tool) => tool.name === "reputation_query_weighted");
      expect(queryTool).toBeDefined();
      expect(weightedTool).toBeDefined();

      const queryResult = parseToolResult(
        await queryTool!.handler({
          context: "concordia-bridge",
        })
      );
      expect(queryResult.bridge_metric_policy).toMatchObject({
        policy: BRIDGE_METRIC_POLICY,
        status: "policy_rated",
        policy_rated_attestations: 1,
        legacy_unbounded_attestations: 0,
      });

      const result = parseToolResult(
        await weightedTool!.handler({
          context: "concordia-bridge",
          metric: "negotiation_round_bucket",
        })
      );

      expect(result.bridge_metric_policy).toMatchObject({
        policy: BRIDGE_METRIC_POLICY,
        status: "policy_rated",
        policy_rated_attestations: 1,
        legacy_unbounded_attestations: 0,
      });
    });

    it("reputation query tools label mixed bridge evidence and keep weighted summaries metric-scoped", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);
      const interactionId = "bridge-policy-mixed";
      const counterpartyDid = "did:key:counterparty";

      await writeMatchingBridgeCommitment(storage, masterKey, identity, encryptionKey, {
        interactionId,
        counterpartyDid,
      });
      await store.record(
        interactionId,
        counterpartyDid,
        {
          type: "negotiation",
          result: "completed",
          metrics: {
            negotiation_round_bucket: 1,
            declared_concession_bucket: 3,
          },
          metric_policy: BRIDGE_METRIC_POLICY,
        },
        "concordia-bridge",
        identity,
        encryptionKey
      );

      await writeBridgeAttestationRecord(
        storage,
        masterKey,
        identity,
        encryptionKey,
        {
          interactionId: "legacy-bridge-mixed",
          counterpartyDid: "did:key:legacy",
          metrics: {
            negotiation_rounds: 4,
            concession_magnitude: 0.25,
          },
        }
      );

      const identityManager = new IdentityManager(storage, masterKey);
      await identityManager.save(identity);
      await identityManager.setPrimary(identity.identity_id);
      const { tools } = createReputationTools(
        storage,
        masterKey,
        identityManager,
        new AuditLog(storage, masterKey)
      );
      const queryTool = tools.find((tool) => tool.name === "reputation_query");
      const weightedTool = tools.find((tool) => tool.name === "reputation_query_weighted");
      expect(queryTool).toBeDefined();
      expect(weightedTool).toBeDefined();

      const queryResult = parseToolResult(
        await queryTool!.handler({ context: "concordia-bridge" })
      );
      expect(queryResult.bridge_metric_policy).toMatchObject({
        policy: BRIDGE_METRIC_POLICY,
        status: "mixed_policy_and_legacy",
        policy_rated_attestations: 1,
        legacy_unbounded_attestations: 1,
        unverified_policy_claim_attestations: 0,
      });
      const querySummary = queryResult.summary as {
        aggregate_metrics: Record<string, unknown>;
      };
      expect(querySummary.aggregate_metrics.negotiation_round_bucket).toBeDefined();
      expect(querySummary.aggregate_metrics.concession_magnitude).toBeUndefined();
      expect(querySummary.aggregate_metrics.negotiation_rounds).toBeUndefined();

      const weightedResult = parseToolResult(
        await weightedTool!.handler({
          context: "concordia-bridge",
          metric: "negotiation_round_bucket",
        })
      );
      expect(weightedResult.bridge_metric_policy).toMatchObject({
        policy: BRIDGE_METRIC_POLICY,
        status: "policy_rated",
        policy_rated_attestations: 1,
        legacy_unbounded_attestations: 0,
        unverified_policy_claim_attestations: 0,
      });
      const unweightedSummary = weightedResult.unweighted_summary as {
        aggregate_metrics: Record<string, unknown>;
      };
      expect(unweightedSummary.aggregate_metrics.negotiation_round_bucket).toBeDefined();
      expect(unweightedSummary.aggregate_metrics.concession_magnitude).toBeUndefined();
      expect(unweightedSummary.aggregate_metrics.negotiation_rounds).toBeUndefined();
    });

    it("reputation query tools redact stored policy claims without local bridge provenance", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await writeBridgeAttestationRecord(
        storage,
        masterKey,
        identity,
        encryptionKey,
        {
          interactionId: "stored-unverified-policy-claim",
          counterpartyDid: "did:key:counterparty",
          metrics: {
            negotiation_round_bucket: 2,
            declared_concession_bucket: 4,
          },
          metricPolicy: BRIDGE_METRIC_POLICY,
        }
      );

      const identityManager = new IdentityManager(storage, masterKey);
      await identityManager.save(identity);
      await identityManager.setPrimary(identity.identity_id);
      const { tools } = createReputationTools(
        storage,
        masterKey,
        identityManager,
        new AuditLog(storage, masterKey)
      );
      const queryTool = tools.find((tool) => tool.name === "reputation_query");
      const weightedTool = tools.find((tool) => tool.name === "reputation_query_weighted");
      expect(queryTool).toBeDefined();
      expect(weightedTool).toBeDefined();

      const queryResult = parseToolResult(
        await queryTool!.handler({ context: "concordia-bridge" })
      );
      expect(queryResult.bridge_metric_policy).toMatchObject({
        policy: BRIDGE_METRIC_POLICY,
        status: "unverified_policy_claims",
        policy_rated_attestations: 0,
        legacy_unbounded_attestations: 0,
        unverified_policy_claim_attestations: 1,
      });
      const querySummary = queryResult.summary as {
        aggregate_metrics: Record<string, unknown>;
        total_interactions: number;
      };
      expect(querySummary.total_interactions).toBe(1);
      expect(querySummary.aggregate_metrics.negotiation_round_bucket).toBeUndefined();
      expect(querySummary.aggregate_metrics.declared_concession_bucket).toBeUndefined();

      const weightedResult = parseToolResult(
        await weightedTool!.handler({
          context: "concordia-bridge",
          metric: "negotiation_round_bucket",
        })
      );
      expect(weightedResult).toMatchObject({
        weighted_score: 0,
        attestation_count: 0,
      });
      expect(weightedResult.bridge_metric_policy).toMatchObject({
        policy: BRIDGE_METRIC_POLICY,
        status: "unverified_policy_claims",
        unverified_policy_claim_attestations: 1,
      });
    });

    it("reputation query labels an empty Concordia-bridge context as having no bridge metric evidence", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const { identity } = setupIdentity(masterKey);
      const identityManager = new IdentityManager(storage, masterKey);
      await identityManager.save(identity);
      await identityManager.setPrimary(identity.identity_id);
      const { tools } = createReputationTools(
        storage,
        masterKey,
        identityManager,
        new AuditLog(storage, masterKey)
      );
      const queryTool = tools.find((tool) => tool.name === "reputation_query");
      expect(queryTool).toBeDefined();

      const result = parseToolResult(
        await queryTool!.handler({ context: "concordia-bridge" })
      );
      expect(result.bridge_metric_policy).toMatchObject({
        policy: BRIDGE_METRIC_POLICY,
        status: "no_bridge_metric_evidence",
        policy_rated_attestations: 0,
        legacy_unbounded_attestations: 0,
      });
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
      const importVerified = await store2.verifyBundleForImport(
        bundle,
        publicKeys
      );
      const standaloneCompleteness = verifyReputationBundleCompleteness(bundle);
      expect(verified).toEqual({
        invalid: 0,
        unverifiable: 0,
        contexts: ["commerce"],
        completeness_verification: "verified",
      });
      expect(importVerified).toEqual(verified);
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

    it("rejects policy-tagged Concordia-bridge imports with raw-term or out-of-policy metrics before any write", async () => {
      const cases: Array<{
        metrics: Record<string, number>;
        message: RegExp;
        key: string;
      }> = [
        {
          metrics: { price: 150 },
          message: /policy bucket metrics/i,
          key: "price",
        },
        {
          metrics: {
            negotiation_round_bucket: 1,
            declared_concession_bucket: 150,
          },
          message: /0 to 10/i,
          key: "declared_concession_bucket",
        },
      ];

      for (const scenario of cases) {
        const storage = new MemoryStorage();
        const masterKey = generateRandomKey();
        const store = new ReputationStore(storage, masterKey);
        const { identity, encryptionKey } = setupIdentity(masterKey);

        await store.record(
          `import-source-${scenario.key}`,
          "did:key:cp1",
          { type: "transaction", result: "completed" },
          "commerce",
          identity,
          encryptionKey
        );

        const tampered = cloneBundle(await store.exportBundle(identity, encryptionKey));
        tampered.attestations[0]!.data.context = "concordia-bridge";
        tampered.attestations[0]!.data.outcome_type = "negotiation";
        tampered.attestations[0]!.data.metrics = scenario.metrics;
        tampered.attestations[0]!.data.metric_policy = BRIDGE_METRIC_POLICY;
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

    it("rejects legacy untagged Concordia-bridge imports with exact metrics before any write", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "legacy-bridge-source",
        "did:key:cp1",
        { type: "transaction", result: "completed" },
        "commerce",
        identity,
        encryptionKey
      );

      const legacyBundle = cloneBundle(
        await store.exportBundle(identity, encryptionKey)
      );
      legacyBundle.attestations[0]!.data.context = "concordia-bridge";
      legacyBundle.attestations[0]!.data.outcome_type = "negotiation";
      legacyBundle.attestations[0]!.data.metrics = {
        negotiation_rounds: 4,
        offers_made: 2,
        concession_magnitude: 0.25,
        response_time_ms: 450,
        reasoning_provided: 1,
      };
      delete legacyBundle.attestations[0]!.data.metric_policy;
      resignAttestationAndBundle(legacyBundle, identity, encryptionKey);

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const publicKeys = publicKeysFor(identity);
      expect(() => store2.verifyBundle(legacyBundle, publicKeys)).toThrow(
        /metric_policy/
      );
      await expect(
        store2.importBundle(legacyBundle, true, publicKeys)
      ).rejects.toThrow(/metric_policy/);
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects policy-rated Concordia-bridge imports without matching local bridge commitment provenance", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "policy-bridge-roundtrip",
        "did:key:cp1",
        { type: "transaction", result: "completed" },
        "commerce",
        identity,
        encryptionKey
      );

      const bundle = cloneBundle(await store.exportBundle(identity, encryptionKey));
      bundle.attestations[0]!.data.context = "concordia-bridge";
      bundle.attestations[0]!.data.outcome_type = "negotiation";
      bundle.attestations[0]!.data.metrics = {
        negotiation_round_bucket: 2,
        declared_offers_made_bucket: 1,
      };
      bundle.attestations[0]!.data.metric_policy = BRIDGE_METRIC_POLICY;
      resignAttestationAndBundle(bundle, identity, encryptionKey);
      expect(bundle.attestations[0]!.data.metric_policy).toBe(
        BRIDGE_METRIC_POLICY
      );

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const publicKeys = publicKeysFor(identity);
      expect(store2.verifyBundle(bundle, publicKeys).invalid).toBe(0);
      await expect(
        store2.verifyBundleForImport(bundle, publicKeys)
      ).rejects.toThrow(/matching local bridge commitments/);
      await expect(
        store2.importBundle(bundle, true, publicKeys)
      ).rejects.toThrow(/matching local bridge commitments/);
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    it("imports policy-rated Concordia-bridge evidence when local commitment outcome matches", async () => {
      const masterKey = generateRandomKey();
      const sourceStorage = new MemoryStorage();
      const sourceStore = new ReputationStore(sourceStorage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);
      const interactionId = "policy-bridge-import-match";
      const counterpartyDid = "did:key:cp1";

      const { outcome } = await writeMatchingBridgeCommitment(
        sourceStorage,
        masterKey,
        identity,
        encryptionKey,
        {
          interactionId,
          counterpartyDid,
          rounds: 9,
        }
      );
      const expectedBucket = bridgeCountBucket(outcome.rounds);

      await sourceStore.record(
        interactionId,
        counterpartyDid,
        {
          type: "negotiation",
          result: "completed",
          metrics: {
            negotiation_round_bucket: expectedBucket,
            declared_offers_made_bucket: 1,
          },
          metric_policy: BRIDGE_METRIC_POLICY,
        },
        "concordia-bridge",
        identity,
        encryptionKey
      );

      const bundle = await sourceStore.exportBundle(identity, encryptionKey);
      const destinationStorage = new MemoryStorage();
      await writeMatchingBridgeCommitment(
        destinationStorage,
        masterKey,
        identity,
        encryptionKey,
        {
          interactionId,
          counterpartyDid,
          rounds: 9,
        }
      );
      const destinationStore = new ReputationStore(
        destinationStorage,
        masterKey
      );
      const publicKeys = publicKeysFor(identity);

      await expect(
        destinationStore.verifyBundleForImport(bundle, publicKeys)
      ).resolves.toMatchObject({
        invalid: 0,
        unverifiable: 0,
        contexts: ["concordia-bridge"],
        completeness_verification: "verified",
      });

      const result = await destinationStore.importBundle(
        bundle,
        true,
        publicKeys
      );
      expect(result.imported).toBe(1);
      expect(result.invalid).toBe(0);
      const summary = await destinationStore.query({
        context: "concordia-bridge",
      });
      expect(summary.total_interactions).toBe(1);
      expect(
        summary.aggregate_metrics.negotiation_round_bucket.mean
      ).toBe(expectedBucket);
    });

    it("rejects policy-rated Concordia-bridge imports when the bucket mismatches local outcome", async () => {
      const masterKey = generateRandomKey();
      const sourceStorage = new MemoryStorage();
      const sourceStore = new ReputationStore(sourceStorage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);
      const interactionId = "policy-bridge-import-bucket-mismatch";
      const counterpartyDid = "did:key:cp1";

      const { outcome } = await writeMatchingBridgeCommitment(
        sourceStorage,
        masterKey,
        identity,
        encryptionKey,
        {
          interactionId,
          counterpartyDid,
          rounds: 9,
        }
      );
      const expectedBucket = bridgeCountBucket(outcome.rounds);

      await sourceStore.record(
        interactionId,
        counterpartyDid,
        {
          type: "negotiation",
          result: "completed",
          metrics: {
            negotiation_round_bucket: expectedBucket,
            declared_offers_made_bucket: 1,
          },
          metric_policy: BRIDGE_METRIC_POLICY,
        },
        "concordia-bridge",
        identity,
        encryptionKey
      );

      const tampered = cloneBundle(
        await sourceStore.exportBundle(identity, encryptionKey)
      );
      tampered.attestations[0]!.data.metrics.negotiation_round_bucket = 1;
      resignAttestationAndBundle(tampered, identity, encryptionKey);

      const destinationStorage = new MemoryStorage();
      await writeMatchingBridgeCommitment(
        destinationStorage,
        masterKey,
        identity,
        encryptionKey,
        {
          interactionId,
          counterpartyDid,
          rounds: 9,
        }
      );
      const destinationStore = new ReputationStore(
        destinationStorage,
        masterKey
      );
      const publicKeys = publicKeysFor(identity);
      expect(destinationStore.verifyBundle(tampered, publicKeys).invalid).toBe(
        0
      );
      await expect(
        destinationStore.verifyBundleForImport(tampered, publicKeys)
      ).rejects.toThrow(/matching local bridge commitments/);
      await expect(
        destinationStore.importBundle(tampered, true, publicKeys)
      ).rejects.toThrow(/matching local bridge commitments/);
      await expect(destinationStorage.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects imported attestations signed by a DID that differs from participant_did", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);
      const other = setupIdentity(masterKey, "other-identity");

      await store.record(
        "signer-participant-mismatch",
        "did:key:cp1",
        { type: "transaction", result: "completed" },
        "commerce",
        identity,
        encryptionKey
      );

      const bundle = cloneBundle(await store.exportBundle(identity, encryptionKey));
      const attestation = bundle.attestations[0]!;
      attestation.signer = other.identity.did;
      attestation.signature = toBase64url(
        sign(
          stringToBytes(JSON.stringify(attestation.data)),
          other.identity.encrypted_private_key,
          other.encryptionKey
        )
      );
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

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const publicKeys = publicKeysFor(identity, other.identity);
      expect(() => store2.verifyBundle(bundle, publicKeys)).toThrow(
        "Reputation bundle contains attestations with invalid or unverifiable signatures"
      );
      await expect(
        store2.importBundle(bundle, true, publicKeys)
      ).rejects.toThrow(
        "Reputation bundle contains attestations with invalid or unverifiable signatures"
      );
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
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

  // ── Attestation-trust hardening (Heralds reputation import path) ─────────
  describe("import-trust hardening", () => {
    // Re-seal a tampered bundle so the completeness manifest and the BUNDLE
    // signature both pass, isolating the per-attestation signature-verification
    // layer as the thing that must reject the forgery. Without this the manifest
    // checksum would trip first (also a valid rejection, but a different layer).
    function resealManifestAndBundle(
      bundle: ReputationBundle,
      exporter: ReturnType<typeof setupIdentity>["identity"],
      exporterKey: Uint8Array
    ): ReputationBundle {
      const rebuilt = cloneBundle(bundle);
      rebuilt.completeness_manifest = buildReputationCompletenessManifest(
        rebuilt.exported_at,
        rebuilt.attestations
      );
      rebuilt.bundle_signature = toBase64url(
        sign(
          reputationBundleSigningBytes(rebuilt),
          exporter.encrypted_private_key,
          exporterKey
        )
      );
      return rebuilt;
    }

    // (1) FORGED IMPORT: a bundle whose per-attestation signature does not match
    // the claimed signer must be REJECTED, not credited, EVEN when the bundle
    // and its completeness manifest are internally consistent.
    it("rejects a forged import whose attestation signature is invalid", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "forge-1", "did:key:cp",
        { type: "transaction", result: "completed", metrics: { rate: 0.9 } },
        "commerce", identity, encryptionKey
      );

      const bundle = await store.exportBundle(identity, encryptionKey);

      // Attacker tampers the signed metric value but leaves the OLD per-att
      // signature, then re-seals the manifest + bundle signature so only the
      // per-attestation signature is now wrong.
      const forged = cloneBundle(bundle);
      forged.attestations[0]!.data.metrics.rate = 1.0;
      const resealed = resealManifestAndBundle(forged, identity, encryptionKey);

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const publicKeys = publicKeysFor(identity);

      // FAIL-BEFORE (regression anchor): must throw, never silently import.
      await expect(
        store2.importBundle(resealed, true, publicKeys)
      ).rejects.toThrow(/invalid or unverifiable signatures/);
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects a forged import whose signer does not match participant_did", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey, "victim");
      const { identity: attacker } = setupIdentity(masterKey, "attacker");

      await store.record(
        "forge-2", "did:key:cp",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey
      );
      const bundle = await store.exportBundle(identity, encryptionKey);

      // Attacker rewrites the signer to their own DID while participant_did stays
      // the victim's, then re-seals so signer !== participant_did is the only
      // defect left for the signature layer to catch.
      const forged = cloneBundle(bundle);
      forged.attestations[0]!.signer = attacker.did;
      const resealed = resealManifestAndBundle(forged, identity, encryptionKey);

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const publicKeys = publicKeysFor(identity, attacker);

      await expect(
        store2.importBundle(resealed, true, publicKeys)
      ).rejects.toThrow(/invalid or unverifiable signatures/);
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    // (3) CRAFTED TIER: a self-signed "verified-sovereign" attestation is a valid
    // signature over a self-asserted tier. Import must accept the signature but
    // must NOT trust the privileged tier: weighted scoring / SHR summary must
    // clamp it to the non-privileged import ceiling (self-attested).
    it("clamps a self-asserted verified-sovereign tier on import so it cannot inflate weight", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      // Attacker self-signs an attestation CLAIMING the top tier.
      await store.record(
        "tier-forge-1", "did:key:cp",
        { type: "transaction", result: "completed", metrics: { rate: 1.0 } },
        "commerce", identity, encryptionKey,
        undefined,
        "verified-sovereign"
      );
      const bundle = await store.exportBundle(identity, encryptionKey);
      // Sanity: the exported claim is indeed the privileged tier.
      expect(bundle.attestations[0]!.data.sovereignty_tier).toBe(
        "verified-sovereign"
      );

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const result = await store2.importBundle(
        bundle, true, publicKeysFor(identity)
      );
      expect(result.imported).toBe(1);
      expect(result.invalid).toBe(0);

      // FAIL-BEFORE: summary tier distribution would have counted this as
      // verified-sovereign. PASS-AFTER: it is clamped to self-attested.
      const summary = await store2.summarizeForSHR();
      expect(summary.tier_distribution["verified-sovereign"]).toBe(0);
      expect(summary.tier_distribution["self-attested"]).toBe(1);

      // Tier scoring sees the clamped tier, not the forged claim.
      const stored = await store2.loadAllForTierScoring({});
      expect(stored).toHaveLength(1);
      expect(trustedSovereigntyTier(stored[0]!)).toBe("self-attested");
      // B2 round-2 finding 2 (boundary chokepoint): the clamp is applied AT the
      // loadAllForTierScoring API, so a caller reading the RAW tier field of the
      // returned scoring view sees the clamped tier WITHOUT having to remember
      // to call trustedSovereigntyTier. FAIL-BEFORE: this field was the forged
      // "verified-sovereign". PASS-AFTER: the boundary returns "self-attested".
      expect(stored[0]!.attestation.data.sovereignty_tier).toBe("self-attested");

      // The forged import must also score as self-attested weight (0.6), never
      // the privileged 1.0, observed through the reputation_query_weighted tool.
      const weighted = await queryWeighted(store2, masterKey, "rate");
      expect(weighted.tier_distribution["verified-sovereign"]).toBe(0);
      expect(weighted.tier_distribution["self-attested"]).toBe(1);
    });

    it("does NOT clamp a locally recorded verified-sovereign tier", async () => {
      // Regression guard: the clamp must apply ONLY to imported attestations.
      // A locally recorded tier came from a handshake this instance witnessed.
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "local-1", "did:key:cp",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey,
        undefined,
        "verified-sovereign"
      );

      const summary = await store.summarizeForSHR();
      expect(summary.tier_distribution["verified-sovereign"]).toBe(1);
      const stored = await store.loadAllForTierScoring({});
      expect(trustedSovereigntyTier(stored[0]!)).toBe("verified-sovereign");
    });

    // Write a StoredAttestation straight into the encrypted _reputation
    // namespace, letting the caller control (or omit) the `imported` field.
    // This reproduces a record persisted BEFORE the provenance marker existed
    // (no `imported` key) or one written with an explicit provenance.
    async function writeStoredAttestationWithProvenance(
      storage: StorageBackend,
      masterKey: Uint8Array,
      identity: ReturnType<typeof setupIdentity>["identity"],
      encryptionKey: Uint8Array,
      opts: {
        attestationId: string;
        sovereigntyTier: SovereigntyTier;
        imported?: boolean;
        includeImportedField: boolean;
      }
    ): Promise<void> {
      const now = new Date().toISOString();
      const data: Attestation["data"] = {
        interaction_id: opts.attestationId,
        participant_did: identity.did,
        counterparty_did: "did:key:cp",
        outcome_type: "transaction",
        outcome_result: "completed",
        metrics: { rate: 1.0 },
        context: "commerce",
        timestamp: now,
        sovereignty_tier: opts.sovereigntyTier,
      };
      const attestation: Attestation = {
        attestation_id: opts.attestationId,
        schema: "sanctuary-interaction-v1",
        data,
        signature: toBase64url(
          sign(
            stringToBytes(JSON.stringify(data)),
            identity.encrypted_private_key,
            encryptionKey
          )
        ),
        signer: identity.did,
      };
      const stored: StoredAttestation = {
        attestation,
        recorded_at: now,
        // Only set the marker when the test asks for it; a legacy record has
        // NO imported key at all.
        ...(opts.includeImportedField ? { imported: opts.imported } : {}),
      };
      const reputationKey = derivePurposeKey(masterKey, "l4-reputation");
      const encrypted = encrypt(
        stringToBytes(JSON.stringify(stored)),
        reputationKey
      );
      await storage.write(
        "_reputation",
        opts.attestationId,
        stringToBytes(JSON.stringify(encrypted))
      );
    }

    // FINDING 1 (legacy-provenance fail-open): a stored attestation with NO
    // `imported` field is unknown-provenance and must FAIL CLOSED (clamped),
    // not be treated as trusted-local. An attestation imported before this
    // patch was written without `imported:true`, so absent-marker MUST clamp.
    it("clamps a legacy record with NO imported field (fail-closed on absent provenance)", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await writeStoredAttestationWithProvenance(
        storage,
        masterKey,
        identity,
        encryptionKey,
        {
          attestationId: "legacy-no-marker",
          sovereigntyTier: "verified-sovereign",
          includeImportedField: false, // legacy: no imported key at all
        }
      );

      const stored = await store.loadAllForTierScoring({});
      expect(stored).toHaveLength(1);
      // Sanity: the field really is absent, so this exercises the fail-closed path.
      expect(stored[0]!.imported).toBeUndefined();

      // FAIL-BEFORE: trustedSovereigntyTier returned "verified-sovereign" for a
      // record whose imported field was undefined (a pre-patch imported claim
      // kept top weight). PASS-AFTER: absent provenance is clamped.
      expect(trustedSovereigntyTier(stored[0]!)).toBe("self-attested");
      // B2 round-2 finding 2 (boundary chokepoint): the RAW tier field of the
      // scoring view returned by loadAllForTierScoring is already clamped, so a
      // caller that reads attestation.data.sovereignty_tier directly (without
      // calling trustedSovereigntyTier) still scores a legacy verified-sovereign
      // record as self-attested. FAIL-BEFORE this was "verified-sovereign".
      expect(stored[0]!.attestation.data.sovereignty_tier).toBe("self-attested");
      const summary = await store.summarizeForSHR();
      expect(summary.tier_distribution["verified-sovereign"]).toBe(0);
      expect(summary.tier_distribution["self-attested"]).toBe(1);

      // End-to-end through the reputation_query_weighted tool: a legacy
      // no-marker verified-sovereign record scores as self-attested weight.
      const weighted = await queryWeighted(store, masterKey, "rate");
      expect(weighted.tier_distribution["verified-sovereign"]).toBe(0);
      expect(weighted.tier_distribution["self-attested"]).toBe(1);
    });

    it("does NOT clamp a record explicitly marked imported:false", async () => {
      // The other half of the fail-closed pair: only a provably-local record
      // (imported === false) escapes the clamp. This is what record() now stamps.
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await writeStoredAttestationWithProvenance(
        storage,
        masterKey,
        identity,
        encryptionKey,
        {
          attestationId: "explicit-local",
          sovereigntyTier: "verified-sovereign",
          imported: false,
          includeImportedField: true,
        }
      );

      const stored = await store.loadAllForTierScoring({});
      expect(stored).toHaveLength(1);
      expect(stored[0]!.imported).toBe(false);
      expect(trustedSovereigntyTier(stored[0]!)).toBe("verified-sovereign");
      // Boundary chokepoint regression: a provably-local record is NOT clamped,
      // so the raw tier field of the scoring view is left at verified-sovereign.
      expect(stored[0]!.attestation.data.sovereignty_tier).toBe(
        "verified-sovereign"
      );
    });

    it("record() stamps genuinely-local attestations with imported:false", async () => {
      // Guard the write side: a locally recorded attestation must carry the
      // explicit local marker so it is correctly NOT clamped, and so it is
      // distinguishable from an unknown-provenance legacy record.
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      const recorded = await store.record(
        "local-marked-1", "did:key:cp",
        { type: "transaction", result: "completed" },
        "commerce", identity, encryptionKey,
        undefined,
        "verified-sovereign"
      );
      expect(recorded.imported).toBe(false);

      const stored = await store.loadAllForTierScoring({});
      expect(stored[0]!.imported).toBe(false);
    });

    // FINDING 2 (signature-verification bypass on import): a missing signer key
    // must make the attestation INVALID and the whole bundle rejected with zero
    // writes. There is no allowUnverifiableAttestations escape on the import
    // path. (Absent / malformed / tampered signatures are covered below.)
    it("rejects an import whose per-attestation signer key is missing (zero writes, no bypass)", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      // Exporter (victim) whose key WILL be supplied, so the bundle-level
      // signature check passes and the per-attestation layer is what must reject.
      const { identity: exporter, encryptionKey: exporterKey } =
        setupIdentity(masterKey, "victim");
      // Stranger who signs the attestation; the importer never learns this key.
      const { identity: stranger, encryptionKey: strangerKey } =
        setupIdentity(masterKey, "stranger");

      await store.record(
        "unknown-signer-1", "did:key:cp",
        { type: "transaction", result: "completed", metrics: { rate: 0.9 } },
        "commerce", exporter, exporterKey
      );
      const bundle = await store.exportBundle(exporter, exporterKey);

      // Rewrite the attestation so BOTH its signer and participant_did are the
      // stranger, and it is validly self-signed by the stranger. This passes the
      // signer===participant_did check, so the ONLY remaining defect is that the
      // importer has no public key for the stranger (unknown signer).
      const forged = cloneBundle(bundle);
      forged.attestations[0]!.data.participant_did = stranger.did;
      forged.attestations[0]!.signer = stranger.did;
      forged.attestations[0]!.signature = toBase64url(
        sign(
          stringToBytes(JSON.stringify(forged.attestations[0]!.data)),
          stranger.encrypted_private_key,
          strangerKey
        )
      );
      const resealed = resealManifestAndBundle(forged, exporter, exporterKey);

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      // Supply ONLY the exporter's key, not the stranger's.
      const publicKeys = publicKeysFor(exporter);

      // FAIL-BEFORE: with the (now removed) allowUnverifiableAttestations option
      // a missing signer key was counted only "unverifiable" and the bundle was
      // still imported. PASS-AFTER: an unknown per-attestation signer is invalid,
      // so the import is refused with no writes.
      await expect(
        store2.importBundle(resealed, true, publicKeys)
      ).rejects.toThrow(/invalid or unverifiable signatures/);
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects an import whose per-attestation signature is absent (zero writes)", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "absent-sig-1", "did:key:cp",
        { type: "transaction", result: "completed", metrics: { rate: 0.9 } },
        "commerce", identity, encryptionKey
      );
      const bundle = await store.exportBundle(identity, encryptionKey);

      // Strip the per-attestation signature entirely, then re-seal manifest +
      // bundle so only the missing per-attestation signature is the defect.
      const forged = cloneBundle(bundle);
      // Cast through unknown: the wire shape may omit a field a strict type
      // requires; this reproduces a hand-crafted bundle with no signature.
      delete (forged.attestations[0]! as unknown as { signature?: string })
        .signature;
      const resealed = resealManifestAndBundle(forged, identity, encryptionKey);

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const publicKeys = publicKeysFor(identity);

      await expect(
        store2.importBundle(resealed, true, publicKeys)
      ).rejects.toThrow(/invalid or unverifiable signatures/);
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects an import whose per-attestation signature is malformed (zero writes)", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "malformed-sig-1", "did:key:cp",
        { type: "transaction", result: "completed", metrics: { rate: 0.9 } },
        "commerce", identity, encryptionKey
      );
      const bundle = await store.exportBundle(identity, encryptionKey);

      // A non-canonical / non-base64url signature string. fromBase64urlStrict
      // rejects it; the lenient decoder used before would have silently coerced
      // trailing junk and let a mangled signature through to verify() as bytes.
      const forged = cloneBundle(bundle);
      forged.attestations[0]!.signature = "!!!not-valid-base64url!!!";
      const resealed = resealManifestAndBundle(forged, identity, encryptionKey);

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const publicKeys = publicKeysFor(identity);

      await expect(
        store2.importBundle(resealed, true, publicKeys)
      ).rejects.toThrow(/invalid or unverifiable signatures/);
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    it("rejects an import whose per-attestation signature is tampered (zero writes)", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "tampered-sig-1", "did:key:cp",
        { type: "transaction", result: "completed", metrics: { rate: 0.9 } },
        "commerce", identity, encryptionKey
      );
      const bundle = await store.exportBundle(identity, encryptionKey);

      // Flip bytes inside a still-canonical base64url signature: it decodes
      // cleanly (strict decode passes) but no longer verifies against the data.
      const forged = cloneBundle(bundle);
      const originalSig = forged.attestations[0]!.signature;
      const sigBytes = fromBase64url(originalSig);
      sigBytes[0]! ^= 0xff;
      forged.attestations[0]!.signature = toBase64url(sigBytes);
      // Sanity: still parseable as base64url, so this exercises verify(), not decode.
      expect(forged.attestations[0]!.signature).not.toBe(originalSig);
      const resealed = resealManifestAndBundle(forged, identity, encryptionKey);

      const storage2 = new MemoryStorage();
      const store2 = new ReputationStore(storage2, masterKey);
      const publicKeys = publicKeysFor(identity);

      await expect(
        store2.importBundle(resealed, true, publicKeys)
      ).rejects.toThrow(/invalid or unverifiable signatures/);
      await expect(storage2.list("_reputation")).resolves.toHaveLength(0);
    });

    // (2) AGGREGATES-ONLY: query must expose aggregate shape only, never raw
    // interaction rows (interaction_id, counterparty DIDs, per-attestation
    // signatures, timestamps of individual interactions).
    it("query returns aggregates only, never raw attestation rows", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ReputationStore(storage, masterKey);
      const { identity, encryptionKey } = setupIdentity(masterKey);

      await store.record(
        "secret-interaction-42", "did:key:secret-counterparty",
        { type: "transaction", result: "completed", metrics: { rate: 0.77 } },
        "commerce", identity, encryptionKey
      );

      const summary = await store.query({ metrics: ["rate"] });
      const serialized = JSON.stringify(summary);

      // No raw identifiers or per-row provenance leak through the aggregate.
      expect(serialized).not.toContain("secret-interaction-42");
      expect(serialized).not.toContain("secret-counterparty");
      expect(serialized).not.toContain(identity.did);
      expect(serialized).not.toContain("signature");
      expect(serialized).not.toContain("attestation_id");

      // The aggregate shape is present.
      expect(summary.total_interactions).toBe(1);
      expect(summary.aggregate_metrics.rate?.mean).toBeCloseTo(0.77);
      expect(Object.keys(summary.aggregate_metrics.rate ?? {}).sort()).toEqual([
        "count", "max", "mean", "median", "min",
      ]);
    });
  });
});
