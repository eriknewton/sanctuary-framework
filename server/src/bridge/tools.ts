/**
 * Sanctuary MCP Server — Concordia Bridge: Tool Definitions
 *
 * MCP tool wrappers for the Concordia-Sanctuary bridge.
 * Three tools:
 *   sanctuary/bridge_commit  — Bind a negotiation outcome to a Sanctuary commitment
 *   sanctuary/bridge_verify  — Verify a commitment against a revealed outcome
 *   sanctuary/bridge_attest  — Record a negotiation as a reputation attestation
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";
import type { StorageBackend } from "../storage/interface.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import type { HandshakeResult } from "../handshake/types.js";
import { ReputationStore } from "../l4-reputation/reputation-store.js";
import { resolveTierByDid, TIER_WEIGHTS, type TierMetadata } from "../l4-reputation/tiers.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { bytesToString } from "../core/encoding.js";
import type { StoredIdentity } from "../core/identity.js";

import {
  createBridgeCommitment,
  verifyBridgeCommitment,
} from "./bridge.js";
import type {
  ConcordiaOutcome,
  BridgeCommitment,
} from "./types.js";

// ─── Bridge Store ────────────────────────────────────────────────────────
// Persists bridge commitments encrypted at rest for later verification
// and attestation linking.

class BridgeStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "bridge-commitments");
  }

  async save(commitment: BridgeCommitment, outcome: ConcordiaOutcome): Promise<void> {
    const record = { commitment, outcome };
    const serialized = stringToBytes(JSON.stringify(record));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_bridge",
      commitment.bridge_commitment_id,
      stringToBytes(JSON.stringify(encrypted))
    );
  }

  async get(
    commitmentId: string
  ): Promise<{ commitment: BridgeCommitment; outcome: ConcordiaOutcome } | null> {
    const raw = await this.storage.read("_bridge", commitmentId);
    if (!raw) return null;

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted));
    } catch {
      return null;
    }
  }
}

// ─── Tool Factory ────────────────────────────────────────────────────────

export function createBridgeTools(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identityManager: IdentityManager,
  auditLog: AuditLog,
  handshakeResults?: Map<string, HandshakeResult>
): { tools: ToolDefinition[] } {
  const bridgeStore = new BridgeStore(storage, masterKey);
  const reputationStore = new ReputationStore(storage, masterKey);
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const hsResults = handshakeResults ?? new Map<string, HandshakeResult>();

  // Helper to resolve identity
  function resolveIdentity(identityId?: string): StoredIdentity {
    const id = identityId
      ? identityManager.get(identityId)
      : identityManager.getDefault();
    if (!id) {
      throw new Error(
        identityId
          ? `Identity "${identityId}" not found`
          : "No identity available. Create one with identity_create first."
      );
    }
    return id;
  }

  const tools: ToolDefinition[] = [
    // ─── bridge_commit ─────────────────────────────────────────────────

    {
      name: "bridge_commit",
      description:
        "Create a cryptographic commitment binding a Concordia negotiation outcome " +
        "to Sanctuary's L3 proof layer. The commitment includes a SHA-256 hash of " +
        "the canonical outcome (hiding + binding), an Ed25519 signature by the " +
        "committer's identity, and an optional Pedersen commitment on the round " +
        "count for zero-knowledge range proofs. This is the Sanctuary side of the " +
        "Concordia bridge — call this when a Concordia `accept` fires.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Concordia session identifier",
          },
          protocol_version: {
            type: "string",
            description: 'Concordia protocol version (e.g., "concordia-v1")',
          },
          proposer_did: {
            type: "string",
            description: "DID of the party who proposed the accepted terms",
          },
          acceptor_did: {
            type: "string",
            description: "DID of the party who accepted",
          },
          terms: {
            type: "object",
            description: "The accepted terms (opaque to Sanctuary, meaningful to Concordia)",
          },
          terms_hash: {
            type: "string",
            description: "SHA-256 hash of the canonical terms serialization (computed by Concordia)",
          },
          rounds: {
            type: "number",
            description: "Number of negotiation rounds (propose/counter cycles)",
          },
          accepted_at: {
            type: "string",
            description: "ISO 8601 timestamp when accept was issued",
          },
          session_receipt: {
            type: "string",
            description: "Optional: signed Concordia session receipt",
          },
          identity_id: {
            type: "string",
            description: "Sanctuary identity to sign the commitment (uses default if omitted)",
          },
          include_pedersen: {
            type: "boolean",
            description: "Include a Pedersen commitment on round count for ZK range proofs",
          },
        },
        required: [
          "session_id",
          "protocol_version",
          "proposer_did",
          "acceptor_did",
          "terms",
          "terms_hash",
          "rounds",
          "accepted_at",
        ],
      },
      handler: async (args) => {
        const outcome: ConcordiaOutcome = {
          session_id: args.session_id as string,
          protocol_version: args.protocol_version as string,
          proposer_did: args.proposer_did as string,
          acceptor_did: args.acceptor_did as string,
          terms: args.terms as Record<string, unknown>,
          terms_hash: args.terms_hash as string,
          rounds: args.rounds as number,
          accepted_at: args.accepted_at as string,
          session_receipt: args.session_receipt as string | undefined,
        };

        const identity = resolveIdentity(args.identity_id as string | undefined);
        const includePedersen = (args.include_pedersen as boolean) ?? false;

        const bridgeCommitment = createBridgeCommitment(
          outcome,
          identity,
          identityEncryptionKey,
          includePedersen
        );

        // Persist the commitment and outcome for later verification/attestation
        await bridgeStore.save(bridgeCommitment, outcome);

        await auditLog.appendCritical({
          layer: "l3",
          operation: "bridge_commit",
          identity_id: identity.identity_id,
          result: "success",
          details: {
            bridge_commitment_id: bridgeCommitment.bridge_commitment_id,
            session_id: outcome.session_id,
            counterparty: outcome.proposer_did === identity.did
              ? outcome.acceptor_did
              : outcome.proposer_did,
          },
        });

        return toolResult({
          bridge_commitment_id: bridgeCommitment.bridge_commitment_id,
          session_id: bridgeCommitment.session_id,
          sha256_commitment: bridgeCommitment.sha256_commitment,
          committer_did: bridgeCommitment.committer_did,
          signature: bridgeCommitment.signature,
          pedersen_commitment: bridgeCommitment.pedersen_commitment
            ? { commitment: bridgeCommitment.pedersen_commitment.commitment }
            : undefined,
          committed_at: bridgeCommitment.committed_at,
          bridge_version: bridgeCommitment.bridge_version,
          note: "Bridge commitment created. The blinding factor is stored encrypted. " +
            "Use bridge_verify to verify the commitment against the revealed outcome. " +
            "Use bridge_attest to link this negotiation to your reputation.",
        });
      },
    },

    // ─── bridge_verify ───────────────────────────────────────────────────

    {
      name: "bridge_verify",
      description:
        "Verify a bridge commitment against a revealed Concordia negotiation outcome. " +
        "Checks SHA-256 commitment validity, Ed25519 signature, session ID match, " +
        "terms hash integrity, and Pedersen commitment (if present). Use this to " +
        "confirm that a counterparty's claimed negotiation outcome matches what was " +
        "cryptographically committed.",
      inputSchema: {
        type: "object",
        properties: {
          bridge_commitment_id: {
            type: "string",
            description: "The bridge commitment ID to verify",
          },
          committer_public_key: {
            type: "string",
            description:
              "The committer's Ed25519 public key (base64url). " +
              "Required if verifying a counterparty's commitment. " +
              "Omit to auto-resolve from local identities.",
          },
        },
        required: ["bridge_commitment_id"],
      },
      handler: async (args) => {
        const commitmentId = args.bridge_commitment_id as string;
        const externalPublicKey = args.committer_public_key as string | undefined;

        // Load the stored commitment and outcome
        const record = await bridgeStore.get(commitmentId);
        if (!record) {
          return toolResult({
            error: `Bridge commitment "${commitmentId}" not found`,
          });
        }

        const { commitment: storedCommitment, outcome } = record;

        // Resolve the committer's public key
        let publicKey: Uint8Array;
        if (externalPublicKey) {
          publicKey = fromBase64url(externalPublicKey);
        } else {
          // Try to find the committer in local identities
          const localIdentities = identityManager.list();
          const match = localIdentities.find((i) => i.did === storedCommitment.committer_did);
          if (!match) {
            return toolResult({
              error: `Cannot resolve public key for committer "${storedCommitment.committer_did}". ` +
                "Provide committer_public_key for external verification.",
            });
          }
          publicKey = fromBase64url(match.public_key);
        }

        const result = verifyBridgeCommitment(storedCommitment, outcome, publicKey);

        auditLog.append("l3", "bridge_verify", "system", {
          bridge_commitment_id: commitmentId,
          session_id: storedCommitment.session_id,
          valid: result.valid,
        });

        return toolResult({
          ...result,
          session_id: storedCommitment.session_id,
          committer_did: storedCommitment.committer_did,
          // SEC-ADD-03: Tag response as containing counterparty-controlled data
          _content_trust: "external",
        });
      },
    },

    // ─── bridge_attest ───────────────────────────────────────────────────

    {
      name: "bridge_attest",
      description:
        "Record a Concordia negotiation as a Sanctuary L4 reputation attestation, " +
        "linked to a bridge commitment. This completes the bridge: the commitment " +
        "(L3) proves the terms were agreed, and the attestation (L4) feeds the " +
        "sovereignty-weighted reputation score. The attestation is automatically " +
        "tagged with the counterparty's sovereignty tier from any completed handshake.",
      inputSchema: {
        type: "object",
        properties: {
          bridge_commitment_id: {
            type: "string",
            description: "The bridge commitment ID to link",
          },
          outcome_result: {
            type: "string",
            enum: ["completed", "partial", "failed", "disputed"],
            description: "Negotiation outcome for reputation scoring",
          },
          metrics: {
            type: "object",
            description:
              "Optional metrics (e.g., rounds, response_time_ms, terms_complexity)",
          },
          identity_id: {
            type: "string",
            description: "Identity to sign the attestation (uses default if omitted)",
          },
        },
        required: ["bridge_commitment_id", "outcome_result"],
      },
      handler: async (args) => {
        const commitmentId = args.bridge_commitment_id as string;
        const outcomeResult = args.outcome_result as
          | "completed"
          | "partial"
          | "failed"
          | "disputed";
        const metrics = (args.metrics as Record<string, number>) ?? {};
        const identityId = args.identity_id as string | undefined;

        // Load the stored commitment and outcome
        const record = await bridgeStore.get(commitmentId);
        if (!record) {
          return toolResult({
            error: `Bridge commitment "${commitmentId}" not found`,
          });
        }

        const { outcome } = record;
        const identity = resolveIdentity(identityId);

        // Determine counterparty DID
        const counterpartyDid =
          outcome.proposer_did === identity.did
            ? outcome.acceptor_did
            : outcome.proposer_did;

        // Resolve sovereignty tier from handshake results
        // Check if the counterparty has a known Sanctuary identity
        const hasSanctuaryIdentity = identityManager.list().some(
          (id) => identityManager.get(id.identity_id)?.did === counterpartyDid
        );
        const tierMeta: TierMetadata = resolveTierByDid(counterpartyDid, hsResults, hasSanctuaryIdentity);
        const tier = tierMeta.sovereignty_tier;

        // Include bridge-specific metrics alongside user-provided ones
        const fullMetrics = {
          ...metrics,
          negotiation_rounds: outcome.rounds,
        };

        // Record the reputation attestation
        const attestation = await reputationStore.record(
          outcome.session_id, // interaction_id = concordia session
          counterpartyDid,
          {
            type: "negotiation",
            result: outcomeResult,
            metrics: fullMetrics,
          },
          "concordia-bridge", // context
          identity,
          identityEncryptionKey,
          undefined, // counterparty_attestation
          tier
        );

        await auditLog.appendCritical({
          layer: "l4",
          operation: "bridge_attest",
          identity_id: identity.identity_id,
          result: "success",
          details: {
            bridge_commitment_id: commitmentId,
            session_id: outcome.session_id,
            attestation_id: attestation.attestation.attestation_id,
            counterparty_did: counterpartyDid,
            sovereignty_tier: tier,
          },
        });

        const weight = TIER_WEIGHTS[tier];

        return toolResult({
          attestation_id: attestation.attestation.attestation_id,
          bridge_commitment_id: commitmentId,
          session_id: outcome.session_id,
          counterparty_did: counterpartyDid,
          outcome_result: outcomeResult,
          sovereignty_tier: tier,
          attested_at: attestation.recorded_at,
          note: `Negotiation recorded as reputation attestation. ` +
            `Counterparty sovereignty tier: ${tier} (weight: ${weight}).`,
        });
      },
    },
  ];

  return { tools };
}
