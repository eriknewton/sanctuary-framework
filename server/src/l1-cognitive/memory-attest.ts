/**
 * Sanctuary MCP Server — L1 Cognitive Sovereignty: Memory Attestation
 *
 * Wraps memory operations (store, retrieve, update, delete, search) in
 * Ed25519-signed attestations. When an agent interacts with any MCP-compatible
 * memory provider (Mem0, Zep, Letta, etc.), this tool creates a cryptographic
 * record: who accessed what, when, and with what result — without storing the
 * memory content itself (content hash only, selective disclosure by design).
 *
 * Tier 3 (auto-allow): this is a read-only audit operation that records
 * that a memory operation happened. It does not modify memory.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { IdentityManager } from "./tools.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import { sign } from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hashToString } from "../core/hashing.js";
import { stringToBytes, toBase64url } from "../core/encoding.js";

// ── Types ──────────────────────────────────────────────────────────────────

/** Valid memory operations */
const VALID_OPERATIONS = [
  "store",
  "retrieve",
  "update",
  "delete",
  "search",
] as const;
type MemoryOperation = (typeof VALID_OPERATIONS)[number];

/** Valid memory scopes */
const VALID_SCOPES = ["user", "agent", "session", "app"] as const;
type MemoryScope = (typeof VALID_SCOPES)[number];

/** Attestation payload (what gets signed) */
interface MemoryAttestationPayload {
  version: 1;
  operation: MemoryOperation;
  provider: string;
  memory_id?: string;
  content_hash: string;
  metadata: {
    user_id?: string;
    agent_id?: string;
    session_id?: string;
    scope?: MemoryScope;
  };
  identity_id: string;
  identity_did: string;
  timestamp: string;
}

/** Full attestation (payload + signature) */
export interface MemoryAttestation {
  attestation_id: string;
  payload: MemoryAttestationPayload;
  signature: string; // base64url Ed25519 signature
  public_key: string; // base64url public key of signer
}

// ── Tool Factory ───────────────────────────────────────────────────────────

export function createMemoryAttestTools(
  identityManager: IdentityManager,
  masterKey: Uint8Array,
  auditLog: AuditLog
): { tools: ToolDefinition[] } {
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");

  const tools: ToolDefinition[] = [
    {
      name: "memory_attest",
      description:
        "Create an Ed25519-signed attestation for a memory operation. " +
        "Records who accessed what (content hash, not content), when, and through " +
        "which memory provider — without exposing the memory content itself. " +
        "Works with any MCP-compatible memory provider (Mem0, Zep, Letta, etc.). " +
        "Use after add_memory, search_memories, or any memory CRUD operation to " +
        "build a cryptographically verifiable audit trail of memory access.",
      inputSchema: {
        type: "object",
        properties: {
          operation: {
            type: "string",
            enum: VALID_OPERATIONS,
            description:
              "The memory operation that was performed: store, retrieve, update, delete, or search.",
          },
          provider: {
            type: "string",
            description:
              'Name of the memory provider (e.g., "mem0", "zep", "letta", "graphiti").',
          },
          content_hash: {
            type: "string",
            description:
              "SHA-256 hash of the memory content (hex or base64url). " +
              "If you have raw content, hash it first — never pass raw memory content to this tool.",
          },
          memory_id: {
            type: "string",
            description:
              "Optional: ID returned by the memory provider for this memory entry.",
          },
          user_id: {
            type: "string",
            description: "Optional: user ID associated with this memory operation.",
          },
          agent_id: {
            type: "string",
            description: "Optional: agent ID that performed the operation.",
          },
          session_id: {
            type: "string",
            description: "Optional: session ID in which the operation occurred.",
          },
          scope: {
            type: "string",
            enum: VALID_SCOPES,
            description:
              'Optional: memory scope — "user" (personal), "agent" (agent-specific), ' +
              '"session" (session-scoped), or "app" (application-wide).',
          },
          identity_id: {
            type: "string",
            description:
              "Optional: Sanctuary identity to sign with. Defaults to primary identity.",
          },
        },
        required: ["operation", "provider", "content_hash"],
      },
      handler: async (args) => {
        // ── Validate operation ─────────────────────────────────────────
        const operation = args.operation as string;
        if (!VALID_OPERATIONS.includes(operation as MemoryOperation)) {
          return toolResult({
            error: `Invalid operation: "${operation}". Must be one of: ${VALID_OPERATIONS.join(", ")}`,
          });
        }

        // ── Validate provider ──────────────────────────────────────────
        const provider = args.provider as string;
        if (!provider || provider.trim().length === 0) {
          return toolResult({ error: "Provider name is required." });
        }
        if (provider.length > 128) {
          return toolResult({
            error: "Provider name exceeds 128 character limit.",
          });
        }

        // ── Validate content_hash ──────────────────────────────────────
        const contentHash = args.content_hash as string;
        if (!contentHash || contentHash.trim().length === 0) {
          return toolResult({ error: "Content hash is required." });
        }
        // Accept hex (64 chars) or base64url (43 chars for 32 bytes)
        if (contentHash.length > 128) {
          return toolResult({
            error: "Content hash exceeds 128 character limit.",
          });
        }

        // ── Resolve identity ───────────────────────────────────────────
        const identityId = args.identity_id as string | undefined;
        const identity = identityId
          ? identityManager.get(identityId)
          : identityManager.getDefault();

        if (!identity) {
          return toolResult({
            error: identityId
              ? `Identity not found: ${identityId}`
              : "No default identity. Create one with identity_create first.",
          });
        }

        // ── Validate optional scope ────────────────────────────────────
        const scope = args.scope as string | undefined;
        if (scope && !VALID_SCOPES.includes(scope as MemoryScope)) {
          return toolResult({
            error: `Invalid scope: "${scope}". Must be one of: ${VALID_SCOPES.join(", ")}`,
          });
        }

        // ── Build attestation payload ──────────────────────────────────
        const timestamp = new Date().toISOString();

        const payload: MemoryAttestationPayload = {
          version: 1,
          operation: operation as MemoryOperation,
          provider: provider.trim(),
          content_hash: contentHash.trim(),
          metadata: {
            ...(args.user_id ? { user_id: args.user_id as string } : {}),
            ...(args.agent_id ? { agent_id: args.agent_id as string } : {}),
            ...(args.session_id
              ? { session_id: args.session_id as string }
              : {}),
            ...(scope ? { scope: scope as MemoryScope } : {}),
          },
          ...(args.memory_id
            ? { memory_id: args.memory_id as string }
            : {}),
          identity_id: identity.identity_id,
          identity_did: identity.did,
          timestamp,
        };

        // ── Sign the payload ───────────────────────────────────────────
        const payloadBytes = stringToBytes(JSON.stringify(payload));
        const signature = sign(
          payloadBytes,
          identity.encrypted_private_key,
          identityEncKey
        );

        // ── Compute attestation ID (deterministic from payload) ────────
        const attestationId = hashToString(payloadBytes).slice(0, 22);

        // ── Record in audit trail ──────────────────────────────────────
        void auditLog.append("l1", `memory_${operation}`, identity.identity_id, {
          attestation_id: attestationId,
          provider: payload.provider,
          content_hash: payload.content_hash,
          memory_id: payload.memory_id,
          scope: payload.metadata.scope,
        });

        // ── Build response ─────────────────────────────────────────────
        const attestation: MemoryAttestation = {
          attestation_id: attestationId,
          payload,
          signature: toBase64url(signature),
          public_key: identity.public_key,
        };

        return toolResult(attestation);
      },
    },
  ];

  return { tools };
}
