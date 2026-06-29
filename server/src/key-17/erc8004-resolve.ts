/**
 * Key 17 -- ERC-8004 Identity verifier (read side).
 *
 * The read counterpart to the ERC-8004 SIGNER (`erc8004-identity-signer.ts` +
 * `erc8004-tools.ts`). Given a presented ERC-8004 agent-identity record, this
 * surface performs OFFLINE verification of its signature and shape against the
 * existing `key-17:erc8004-identity:v1` signing scheme (it reuses the signer's
 * verify path; it defines NO new crypto label and derives NO key material).
 *
 * Default behavior is purely local: it makes NO outbound request and never
 * touches a chain. Resolution is fail-closed: any malformed, unsigned, or
 * tampered record resolves to `valid: false`, never to a soft pass.
 *
 * Trust note (read by an AI agent deciding whether to call the tool):
 * `valid: true` always proves the presented record carries a self-consistent
 * secp256k1 signature recoverable to the embedded `signer_address`. It does
 * NOT by itself prove that `signer_address` is the registered owner of the
 * identity on any chain. If, and only if, operator config enables registry
 * confirmation and the gated ownerOf read succeeds, the result's assurance is
 * upgraded from `offline_verified` to `registry_confirmed`.
 */

import { randomUUID } from "node:crypto";

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import {
  verifyErc8004Registration,
  type SignedErc8004Registration,
} from "./erc8004-identity-signer.js";
import {
  confirmErc8004RegistryOwner,
  type Erc8004RegistryConfirmation,
  type Erc8004RegistryConfirmationConfig,
  type Erc8004RegistryEgressGate,
  type Erc8004RegistryFetch,
} from "./erc8004-registry-confirm.js";

// ── Audit ops ────────────────────────────────────────────────────────

export const ERC8004_RESOLVE_AUDIT_OPS = {
  REQUESTED: "erc8004.resolve.requested",
  RESOLVED_VALID: "erc8004.resolve.valid",
  RESOLVED_INVALID: "erc8004.resolve.invalid",
  REGISTRY_CONFIRMED: "erc8004.resolve.registry_confirmed",
  REGISTRY_UNCONFIRMED: "erc8004.resolve.registry_unconfirmed",
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
  /** `valid` is offline verification; `assurance` says whether registry confirmation upgraded it. */
  assurance?: "offline_verified" | "registry_confirmed";
  reason?: string;
  /** Recovered/verified signer address (present only when `valid`). */
  signer_address?: string;
  /** Optional on-chain owner confirmation, default-off and fail-closed. */
  registry_confirmation?: Erc8004RegistryConfirmation;
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
  registryConfirmation?: Erc8004RegistryConfirmationConfig;
  egressGate?: Erc8004RegistryEgressGate;
  fetchFn?: Erc8004RegistryFetch;
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

  const registryConfirmation = await confirmErc8004RegistryOwner(
    {
      config: deps.registryConfirmation ?? {
        enabled: false,
        rpc_url: "",
        chain_id: signed.chain_id,
        timeout_ms: 10_000,
      },
      egressGate: deps.egressGate,
      fetchFn: deps.fetchFn,
    },
    {
      identity: signed.identity,
      registry: signed.registry,
      chain_id: signed.chain_id,
      signer_address: signed.signer_address,
    },
  );

  if (registryConfirmation.status === "confirmed") {
    await deps.auditLog.append(
      "l2",
      ERC8004_RESOLVE_AUDIT_OPS.REGISTRY_CONFIRMED,
      deps.identityId,
      {
        request_id: requestId,
        registry: signed.registry,
        chain_id: signed.chain_id,
        fortress_id: deps.fortressId,
      },
    );
  } else if (registryConfirmation.status === "unconfirmed") {
    await deps.auditLog.append(
      "l2",
      ERC8004_RESOLVE_AUDIT_OPS.REGISTRY_UNCONFIRMED,
      deps.identityId,
      {
        request_id: requestId,
        registry: signed.registry,
        chain_id: signed.chain_id,
        reason: registryConfirmation.reason,
        fortress_id: deps.fortressId,
      },
    );
  }

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
    assurance:
      registryConfirmation.status === "confirmed"
        ? "registry_confirmed"
        : "offline_verified",
    signer_address: signed.signer_address,
    registry_confirmation: registryConfirmation,
    fields,
  };
}

// ── MCP tool definition ──────────────────────────────────────────────

export interface Erc8004ResolveToolsOptions {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  registryConfirmation?: Erc8004RegistryConfirmationConfig;
  egressGate?: Erc8004RegistryEgressGate;
  fetchFn?: Erc8004RegistryFetch;
}

export function createErc8004ResolveTools(
  opts: Erc8004ResolveToolsOptions,
): { tools: ToolDefinition[] } {
  const tools: ToolDefinition[] = [
    {
      name: "sanctuary/resolve_erc8004_identity",
      tool_class: "read",
      description:
        "Verify a presented ERC-8004 agent-identity record. By default this " +
        "is an offline-only, read-only local check that recomputes the " +
        "record's signature against the embedded signer address and returns " +
        "valid/invalid plus the verified identity fields. A valid result is " +
        "offline-verified only: it proves the record carries a self-consistent " +
        "secp256k1 signature recoverable to signer_address, not that the signer " +
        "is the registry owner. If the operator explicitly enables ERC-8004 " +
        "registry confirmation and configures an RPC endpoint, Sanctuary makes " +
        "a gated ownerOf(identity) read through the egress gate and returns " +
        "registry_confirmation plus assurance=registry_confirmed only on an " +
        "owner match. Unavailable RPC, denied egress, or owner mismatch remains " +
        "unconfirmed and never becomes a false confirmed claim. Never returns " +
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
            registryConfirmation: opts.registryConfirmation,
            egressGate: opts.egressGate,
            fetchFn: opts.fetchFn,
          },
          (args as Record<string, unknown>).record,
        );
        return toolResult(result);
      },
    },
  ];

  return { tools };
}
