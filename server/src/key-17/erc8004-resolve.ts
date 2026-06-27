/**
 * Key 17 -- ERC-8004 Identity OFFLINE verifier (read side).
 *
 * The read counterpart to the ERC-8004 SIGNER (`erc8004-identity-signer.ts` +
 * `erc8004-tools.ts`). Given a presented ERC-8004 agent-identity record, this
 * surface performs OFFLINE verification of its signature and shape against the
 * existing `key-17:erc8004-identity:v1` signing scheme (it reuses the signer's
 * verify path; it defines NO new crypto label and derives NO key material).
 *
 * This is purely local: it makes NO outbound request and never touches a chain.
 * Resolution is fail-closed: any malformed, unsigned, or tampered record
 * resolves to `valid: false`, never to a soft pass.
 *
 * Trust note (read by an AI agent deciding whether to call the tool):
 * a `valid: true` result proves only that the presented record carries a
 * self-consistent secp256k1 signature recoverable to the embedded
 * `signer_address`. It does NOT prove that `signer_address` is the registered
 * owner of the identity on any chain.
 *
 * DEBT: on-chain registry confirmation (proving the signer is the registry's
 * recorded owner) is a deliberate follow-up, NOT shipped here. When it lands it
 * MUST reuse Verascore's proven ERC-8004 ABI (`ownerOf(uint256)` against the
 * real registry) per the Sanctuary implementation-lane rule (consume the proven
 * spec), routed through the standard SSRF-guarded outbound path. It must NOT
 * reintroduce a hand-rolled call encoder: the prior placeholder emitted a zero
 * selector and ABI-encoded the identity as a dynamic `string`, which a real
 * registry can never satisfy, so any "confirmed" claim it produced would be an
 * overclaim.
 */

import { randomUUID } from "node:crypto";

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import {
  verifyErc8004Registration,
  type SignedErc8004Registration,
} from "./erc8004-identity-signer.js";

// ── Audit ops ────────────────────────────────────────────────────────

export const ERC8004_RESOLVE_AUDIT_OPS = {
  REQUESTED: "erc8004.resolve.requested",
  RESOLVED_VALID: "erc8004.resolve.valid",
  RESOLVED_INVALID: "erc8004.resolve.invalid",
} as const;

/**
 * Outcome of OFFLINE-verifying a presented ERC-8004 identity record.
 *
 *  - `valid`         : the offline signature/shape check passed.
 *  - `signer_address`: the address recovered from (and matching) the record.
 *  - `fields`        : the verified, non-sensitive identity fields.
 *
 * There is deliberately no on-chain field: this surface only proves the record
 * is internally self-consistent, never that the signer is the registry's owner.
 */
export interface Erc8004ResolveResult {
  request_id: string;
  valid: boolean;
  reason?: string;
  /** Recovered/verified signer address (present only when `valid`). */
  signer_address?: string;
  /** Verified, non-sensitive identity fields echoed back for the caller. */
  fields?: {
    identity: string;
    registry: string;
    chain_id: number;
    nonce: number;
    timestamp: string;
  };
}

export interface Erc8004ResolveDeps {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
}

/**
 * Coerce an unknown presented record into a `SignedErc8004Registration`,
 * failing closed on any missing/wrong-typed required field. We do NOT trust the
 * caller's shape; this is the trust-boundary check before any crypto runs.
 */
function coercePresentedRecord(
  record: unknown,
):
  | { ok: true; signed: SignedErc8004Registration }
  | { ok: false; reason: string } {
  if (typeof record !== "object" || record === null) {
    return { ok: false, reason: "record must be an object" };
  }
  const r = record as Record<string, unknown>;

  const requireString = (k: string): string | null =>
    typeof r[k] === "string" && (r[k] as string).length > 0
      ? (r[k] as string)
      : null;

  const identity = requireString("identity");
  const registry = requireString("registry");
  const timestamp = requireString("timestamp");
  const signature = requireString("signature");
  const signer_address = requireString("signer_address");
  const public_key = requireString("public_key");
  const chain_id = r["chain_id"];
  const nonce = r["nonce"];

  const missing: string[] = [];
  if (identity === null) missing.push("identity");
  if (registry === null) missing.push("registry");
  if (timestamp === null) missing.push("timestamp");
  if (signature === null) missing.push("signature");
  if (signer_address === null) missing.push("signer_address");
  if (public_key === null) missing.push("public_key");
  if (typeof chain_id !== "number" || !Number.isInteger(chain_id)) {
    missing.push("chain_id");
  }
  if (typeof nonce !== "number" || !Number.isInteger(nonce)) {
    missing.push("nonce");
  }
  if (missing.length > 0) {
    return {
      ok: false,
      reason: `record is missing or malformed required field(s): ${missing.join(", ")}`,
    };
  }

  // Reconstruct preserving any extra metadata fields the signer may have
  // canonicalized over (e.g. metadata_uri). We keep all enumerable keys so the
  // canonical-JSON recomputation inside verify matches what was signed.
  return {
    ok: true,
    signed: {
      ...(r as object),
      identity: identity as string,
      registry: registry as string,
      chain_id: chain_id as number,
      nonce: nonce as number,
      timestamp: timestamp as string,
      signature: signature as string,
      signer_address: signer_address as string,
      public_key: public_key as string,
    } as SignedErc8004Registration,
  };
}

/**
 * OFFLINE-verify a presented ERC-8004 identity record.
 *
 * Performs the offline signature/shape check (fail-closed). Makes no outbound
 * request and no on-chain read.
 */
export async function resolveErc8004Identity(
  deps: Erc8004ResolveDeps,
  presented: unknown,
): Promise<Erc8004ResolveResult> {
  const requestId = randomUUID();

  await deps.auditLog.append(
    "l2",
    ERC8004_RESOLVE_AUDIT_OPS.REQUESTED,
    deps.identityId,
    { request_id: requestId, fortress_id: deps.fortressId },
  );

  // ── Trust-boundary shape check (fail closed) ──────────────────────
  const coerced = coercePresentedRecord(presented);
  if (!coerced.ok) {
    await deps.auditLog.append(
      "l2",
      ERC8004_RESOLVE_AUDIT_OPS.RESOLVED_INVALID,
      deps.identityId,
      { request_id: requestId, reason: coerced.reason, fortress_id: deps.fortressId },
    );
    return { request_id: requestId, valid: false, reason: coerced.reason };
  }

  const signed = coerced.signed;

  // ── Offline signature verification (reuses the signer's verify path) ──
  let offlineValid: boolean;
  try {
    offlineValid = verifyErc8004Registration(signed);
  } catch {
    offlineValid = false;
  }

  if (!offlineValid) {
    await deps.auditLog.append(
      "l2",
      ERC8004_RESOLVE_AUDIT_OPS.RESOLVED_INVALID,
      deps.identityId,
      {
        request_id: requestId,
        reason: "signature_verification_failed",
        registry: signed.registry,
        chain_id: signed.chain_id,
        fortress_id: deps.fortressId,
      },
    );
    return {
      request_id: requestId,
      valid: false,
      reason: "signature_verification_failed",
    };
  }

  const fields = {
    identity: signed.identity,
    registry: signed.registry,
    chain_id: signed.chain_id,
    nonce: signed.nonce,
    timestamp: signed.timestamp,
  };

  await deps.auditLog.append(
    "l2",
    ERC8004_RESOLVE_AUDIT_OPS.RESOLVED_VALID,
    deps.identityId,
    {
      request_id: requestId,
      signer_address: signed.signer_address,
      registry: signed.registry,
      chain_id: signed.chain_id,
      fortress_id: deps.fortressId,
    },
  );
  return {
    request_id: requestId,
    valid: true,
    signer_address: signed.signer_address,
    fields,
  };
}

// ── MCP tool definition ──────────────────────────────────────────────

export interface Erc8004ResolveToolsOptions {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
}

export function createErc8004ResolveTools(
  opts: Erc8004ResolveToolsOptions,
): { tools: ToolDefinition[] } {
  const tools: ToolDefinition[] = [
    {
      name: "sanctuary/resolve_erc8004_identity",
      tool_class: "read",
      description:
        "Verify a presented ERC-8004 agent-identity record OFFLINE. This is a " +
        "read-only, fully local check: it recomputes the record's signature " +
        "against the embedded signer address and returns valid/invalid plus " +
        "the verified identity fields. A valid result proves only that the " +
        "record carries a self-consistent secp256k1 signature recoverable to " +
        "its signer_address; it does NOT prove the signer is the registry's " +
        "recorded owner on any chain. Makes no outbound request. Never returns " +
        "key material.",
      inputSchema: {
        type: "object",
        properties: {
          record: {
            type: "object",
            description:
              "The presented ERC-8004 identity record to verify, including " +
              "identity, registry, chain_id, nonce, timestamp, signature, " +
              "signer_address, and public_key as produced by the signer.",
          },
        },
        required: ["record"],
      },
      handler: async (args) => {
        const result = await resolveErc8004Identity(
          {
            auditLog: opts.auditLog,
            identityId: opts.identityId,
            fortressId: opts.fortressId,
          },
          (args as Record<string, unknown>).record,
        );
        return toolResult(result);
      },
    },
  ];

  return { tools };
}
