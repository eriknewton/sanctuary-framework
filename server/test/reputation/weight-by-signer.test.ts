/**
 * Reputation signer-tier weighting tests.
 *
 * These use the real MCP record/query tools so the recorded tier and weighted
 * score are exercised through the same path an agent calls.
 */

import { describe, expect, it } from "vitest";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toBase64url } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import type { HandshakeResult } from "../../src/handshake/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createReputationTools } from "../../src/reputation/tools.js";
import type { SovereigntyTier } from "../../src/reputation/tiers.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { SignedSHR } from "../../src/shr/types.js";
import type { ToolDefinition } from "../../src/router.js";

type CreatedIdentity = ReturnType<typeof createIdentity>;

function parseToolResult(
  result: Awaited<ReturnType<ToolDefinition["handler"]>>
): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function shrFor(identity: CreatedIdentity, instanceId: string): SignedSHR {
  return {
    body: {
      shr_version: "1.0",
      implementation: {
        sanctuary_version: "0.4.0",
        node_version: "20.0.0",
        generated_by: "sanctuary-mcp-server",
      },
      instance_id: instanceId,
      generated_at: "2026-08-09T12:00:00.000Z",
      expires_at: "2099-01-01T00:00:00.000Z",
      layers: {
        l1: {
          status: "active",
          encryption: "aes-256-gcm",
          key_custody: "self",
          integrity: "merkle-sha256",
          identity_type: "ed25519",
          state_portable: true,
        },
        l2: {
          status: "active",
          isolation_type: "local-process",
          attestation_available: true,
        },
        l3: {
          status: "active",
          proof_system: "schnorr-pedersen",
          selective_disclosure: true,
        },
        l4: {
          status: "active",
          reputation_mode: "self-custodied",
          attestation_format: "eas-compatible",
          reputation_portable: true,
        },
      },
      capabilities: {
        handshake: true,
        shr_exchange: true,
        reputation_verify: true,
        encrypted_channel: false,
      },
      degradations: [],
    },
    signed_by: identity.storedIdentity.public_key,
    signature_scheme: "ed25519-v1",
    signature: toBase64url(hash(new Uint8Array([1, 2, 3]))),
  };
}

function verifiedHandshake(
  identity: CreatedIdentity,
  instanceId: string,
  tier: "verified-sovereign" | "verified-degraded"
): HandshakeResult {
  return {
    counterparty_id: instanceId,
    counterparty_shr: shrFor(identity, instanceId),
    verified: true,
    sovereignty_level: tier === "verified-sovereign" ? "full" : "degraded",
    trust_tier: tier,
    completed_at: "2026-08-09T12:00:00.000Z",
    expires_at: "2099-01-01T00:00:00.000Z",
    errors: [],
    liveness_proven: true,
  };
}

async function setupHarness(
  handshakesFor: (identities: {
    signerA: CreatedIdentity;
    signerB: CreatedIdentity;
    counterparty: CreatedIdentity;
  }) => Map<string, HandshakeResult>
) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const identityEncryptionKey = derivePurposeKey(
    masterKey,
    "identity-encryption"
  );
  const signerA = createIdentity(
    "self-attested-signer",
    identityEncryptionKey,
    "recovery-key"
  );
  const signerB = createIdentity(
    "verified-signer",
    identityEncryptionKey,
    "recovery-key"
  );
  const counterparty = createIdentity(
    "verified-counterparty",
    identityEncryptionKey,
    "recovery-key"
  );
  const identityManager = new IdentityManager(storage, masterKey);

  await identityManager.save(signerA.storedIdentity);
  await identityManager.save(signerB.storedIdentity);
  await identityManager.setPrimary(signerA.storedIdentity.identity_id);

  const handshakes = handshakesFor({ signerA, signerB, counterparty });
  const { tools } = createReputationTools(
    storage,
    masterKey,
    identityManager,
    new AuditLog(storage, masterKey),
    handshakes
  );
  const byName = (name: string): ToolDefinition => {
    const tool = tools.find((t) => t.name === name);
    if (!tool) throw new Error(`Missing tool: ${name}`);
    return tool;
  };

  return {
    byName,
    signerA,
    signerB,
    counterparty,
  };
}

describe("reputation weighting by signer", () => {
  it("weights a local record by the self-attested signer, not the verified counterparty", async () => {
    const { byName, counterparty } = await setupHarness(({ counterparty }) => {
      const handshakes = new Map<string, HandshakeResult>();
      handshakes.set(
        "counterparty-instance",
        verifiedHandshake(
          counterparty,
          "counterparty-instance",
          "verified-sovereign"
        )
      );
      return handshakes;
    });

    const record = parseToolResult(
      await byName("reputation_record").handler({
        interaction_id: "verified-counterparty-self-signer",
        counterparty_did: counterparty.publicIdentity.did,
        outcome: {
          type: "transaction",
          result: "completed",
          metrics: { fulfillment_rate: 1 },
        },
      })
    );

    expect(record.sovereignty_tier).toBe("self-attested");

    const weighted = parseToolResult(
      await byName("reputation_query_weighted").handler({
        counterparty_did: counterparty.publicIdentity.did,
        metric: "fulfillment_rate",
      })
    );
    expect(weighted.weighted_score).toBe(1);
    expect(weighted.tier_distribution).toMatchObject({
      "verified-sovereign": 0,
      "self-attested": 1,
    });
  });

  it("weights records about the same counterparty differently by signer tier", async () => {
    const { byName, signerB, counterparty } = await setupHarness(
      ({ signerB, counterparty }) => {
        const handshakes = new Map<string, HandshakeResult>();
        handshakes.set(
          "counterparty-instance",
          verifiedHandshake(
            counterparty,
            "counterparty-instance",
            "verified-sovereign"
          )
        );
        handshakes.set(
          "verified-signer-instance",
          verifiedHandshake(
            signerB,
            "verified-signer-instance",
            "verified-sovereign"
          )
        );
        return handshakes;
      }
    );

    await byName("reputation_record").handler({
      interaction_id: "same-counterparty-self-signer",
      counterparty_did: counterparty.publicIdentity.did,
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { quality: 0 },
      },
    });
    await byName("reputation_record").handler({
      interaction_id: "same-counterparty-verified-signer",
      counterparty_did: counterparty.publicIdentity.did,
      identity_id: signerB.storedIdentity.identity_id,
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { quality: 1 },
      },
    });

    const weighted = parseToolResult(
      await byName("reputation_query_weighted").handler({
        counterparty_did: counterparty.publicIdentity.did,
        metric: "quality",
      })
    );

    expect(weighted.tier_distribution).toMatchObject({
      "verified-sovereign": 1,
      "self-attested": 1,
    });
    expect(weighted.weighted_score).toBeCloseTo(1 / 1.5, 8);
  });

  it("does not confirm arbitrary counterparty attestation text", async () => {
    const { byName, counterparty } = await setupHarness(
      () => new Map<string, HandshakeResult>()
    );

    const record = parseToolResult(
      await byName("reputation_record").handler({
        interaction_id: "unverified-counterparty-attachment",
        counterparty_did: counterparty.publicIdentity.did,
        counterparty_attestation: "definitely signed by the counterparty",
        outcome: {
          type: "service",
          result: "completed",
          metrics: { satisfaction: 1 },
        },
      })
    );

    expect(record.counterparty_confirmed).toBe(false);
  });
});
