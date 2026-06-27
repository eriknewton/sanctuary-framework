/**
 * Key 17 -- ERC-8004 Identity Registry RESOLVE (read side).
 *
 * The read counterpart to the ERC-8004 SIGNER (`erc8004-identity-signer.ts` +
 * `erc8004-tools.ts`). Given a presented ERC-8004 agent-identity record, this
 * surface performs OFFLINE verification of its signature and shape against the
 * existing `key-17:erc8004-identity:v1` signing scheme (it reuses the signer's
 * verify path; it defines NO new crypto label and derives NO key material).
 *
 * Optionally, when (and only when) the operator supplies an RPC endpoint, the
 * resolver may read the registry on-chain. That read is DEFAULT-OFF: with no
 * endpoint configured the tool does offline verification only and never makes
 * any outbound request. Any outbound RPC routes through the standard outbound
 * path and is guarded by the same SSRF validator used elsewhere in the server
 * (`proxy/ssrf-validator.ts`); this module never opens a raw second socket and
 * never auto-egresses without an operator-configured endpoint.
 *
 * Castle-walking: with no `rpcEndpoint` configured there is no outbound
 * surface at all. Resolution is fail-closed: any malformed, unsigned, or
 * tampered record resolves to `valid: false`, never to a soft pass.
 *
 * Trust note (read by an AI agent deciding whether to call the tool):
 * a `valid: true` result proves only that the presented record carries a
 * self-consistent secp256k1 signature recoverable to the embedded
 * `signer_address`. It does NOT prove that `signer_address` is the registered
 * owner of the identity on any chain unless `registry_confirmed` is also true,
 * which requires the operator to have supplied a registry RPC endpoint.
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
  validateUpstreamSseUrl,
  type SsrfValidationResult,
} from "../proxy/ssrf-validator.js";

// ── Audit ops ────────────────────────────────────────────────────────

export const ERC8004_RESOLVE_AUDIT_OPS = {
  REQUESTED: "erc8004.resolve.requested",
  RESOLVED_VALID: "erc8004.resolve.valid",
  RESOLVED_INVALID: "erc8004.resolve.invalid",
  RPC_BLOCKED: "erc8004.resolve.rpc_blocked",
  RPC_CONFIRMED: "erc8004.resolve.rpc_confirmed",
  RPC_FAILED: "erc8004.resolve.rpc_failed",
} as const;

/**
 * Outcome of resolving a presented ERC-8004 identity record.
 *
 * Field semantics are deliberately separated so a caller can never confuse an
 * offline signature check with an on-chain registry confirmation:
 *  - `valid`            : the offline signature/shape check passed.
 *  - `signer_address`   : the address recovered from (and matching) the record.
 *  - `registry_confirmed`: true ONLY when an operator-supplied RPC endpoint
 *                          confirmed the binding on-chain; `undefined` when no
 *                          endpoint was configured (offline-only resolution).
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
  /**
   * On-chain confirmation status. Omitted when no RPC endpoint was supplied
   * (offline-only). `false` when an endpoint was supplied but the binding
   * could not be confirmed (read failed or did not match).
   */
  registry_confirmed?: boolean;
  /** Human-readable note about the on-chain read, when one was attempted. */
  registry_note?: string;
}

/** Minimal fetch shape used for the optional RPC read (injectable for tests). */
export type ResolveFetch = (
  input: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal;
  },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface Erc8004ResolveDeps {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  /**
   * Operator-supplied registry RPC endpoint. DEFAULT-OFF: when omitted the
   * resolver does offline verification only and never makes any outbound
   * request. Must be an http(s) URL; private/loopback/metadata targets are
   * rejected by the SSRF validator (use `allowPrivateRpc` to opt in).
   */
  rpcEndpoint?: string;
  /** Opt-in: allow the RPC endpoint to point at a private/LAN address. */
  allowPrivateRpc?: boolean;
  /** Injectable fetch for the optional RPC read. Defaults to global fetch. */
  resolveFetch?: ResolveFetch;
  /** RPC read timeout in ms. Default 5000. */
  rpcTimeoutMs?: number;
}

const DEFAULT_RPC_TIMEOUT_MS = 5000;

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

function describeSsrfRejection(result: SsrfValidationResult): string {
  return result.ok ? "ok" : `rpc endpoint rejected: ${result.reason}`;
}

/**
 * Resolve a presented ERC-8004 identity record.
 *
 * Always performs the offline signature/shape check first (fail-closed). Only
 * if that passes AND an operator RPC endpoint is configured does it attempt the
 * on-chain registry confirmation through the SSRF-guarded outbound path.
 */
export async function resolveErc8004Identity(
  deps: Erc8004ResolveDeps,
  presented: unknown,
): Promise<Erc8004ResolveResult> {
  const requestId = randomUUID();

  void deps.auditLog.append(
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

  // ── Optional on-chain confirmation (DEFAULT-OFF) ──────────────────
  // No endpoint -> offline-only result, NO outbound request ever.
  if (!deps.rpcEndpoint) {
    await deps.auditLog.append(
      "l2",
      ERC8004_RESOLVE_AUDIT_OPS.RESOLVED_VALID,
      deps.identityId,
      {
        request_id: requestId,
        signer_address: signed.signer_address,
        registry: signed.registry,
        chain_id: signed.chain_id,
        registry_confirmed: false,
        offline_only: true,
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

  // An endpoint was configured: SSRF-guard it before any outbound call.
  const ssrf = await validateUpstreamSseUrl(deps.rpcEndpoint, {
    allowPrivateNetworks: deps.allowPrivateRpc === true,
  });
  if (!ssrf.ok) {
    const note = describeSsrfRejection(ssrf);
    await deps.auditLog.append(
      "l2",
      ERC8004_RESOLVE_AUDIT_OPS.RPC_BLOCKED,
      deps.identityId,
      { request_id: requestId, reason: ssrf.reason, fortress_id: deps.fortressId },
    );
    // The offline check still passed; surface that with an unconfirmed registry
    // status and the block reason. Fail-closed on the registry claim only.
    return {
      request_id: requestId,
      valid: true,
      signer_address: signed.signer_address,
      fields,
      registry_confirmed: false,
      registry_note: note,
    };
  }

  // Perform the on-chain read through the standard outbound fetch path.
  const doFetch: ResolveFetch =
    deps.resolveFetch ??
    ((input, init) =>
      fetch(input, init) as unknown as ReturnType<ResolveFetch>);

  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    deps.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS,
  );

  let confirmed = false;
  let note: string;
  try {
    // ERC-8004 Identity Registry exposes the agent owner via a standard
    // read. We issue a JSON-RPC eth_call and treat a returned address that
    // matches the recovered signer as confirmation. We deliberately keep the
    // claim narrow: any read error or mismatch yields registry_confirmed=false.
    const resp = await doFetch(deps.rpcEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: requestId,
        method: "eth_call",
        params: [
          {
            to: signed.registry,
            data: encodeOwnerOfCall(signed.identity),
          },
          "latest",
        ],
      }),
      signal: controller.signal,
    });

    if (!resp.ok) {
      note = `registry rpc returned status ${resp.status}`;
    } else {
      const body = (await resp.json().catch(() => null)) as {
        result?: unknown;
        error?: unknown;
      } | null;
      if (!body || body.error || typeof body.result !== "string") {
        note = "registry rpc returned no usable result";
      } else {
        const onChainAddress = decodeAddressResult(body.result);
        if (
          onChainAddress &&
          onChainAddress.toLowerCase() === signed.signer_address.toLowerCase()
        ) {
          confirmed = true;
          note = "registry confirms signer is the registered owner";
        } else {
          note = "registry owner does not match presented signer";
        }
      }
    }
  } catch (err) {
    note =
      err instanceof Error && err.name === "AbortError"
        ? "registry rpc timed out"
        : "registry rpc request failed";
  } finally {
    clearTimeout(timer);
  }

  await deps.auditLog.append(
    "l2",
    confirmed
      ? ERC8004_RESOLVE_AUDIT_OPS.RPC_CONFIRMED
      : ERC8004_RESOLVE_AUDIT_OPS.RPC_FAILED,
    deps.identityId,
    {
      request_id: requestId,
      registry: signed.registry,
      chain_id: signed.chain_id,
      registry_confirmed: confirmed,
      fortress_id: deps.fortressId,
    },
  );

  return {
    request_id: requestId,
    valid: true,
    signer_address: signed.signer_address,
    fields,
    registry_confirmed: confirmed,
    registry_note: note,
  };
}

/**
 * Encode an `ownerOf(string)`-style read selector for the identity. The exact
 * registry ABI is operator/registry-specific; we keep this a thin, side-effect
 * free encoder (selector + abi-encoded string) so the read is deterministic and
 * never throws. Resolution treats any decode mismatch as unconfirmed, so an
 * imperfect selector can only ever DOWNGRADE the claim, never forge it.
 */
function encodeOwnerOfCall(identity: string): string {
  // keccak256("ownerOf(string)") first 4 bytes is registry-specific; we expose
  // the identity as an abi-encoded dynamic string offset/length/data so a
  // conforming registry can decode it. We intentionally do not hardcode a
  // selector here; the head is a zero selector placeholder that a conforming
  // RPC gateway maps, and a non-conforming one returns an error (-> unconfirmed).
  const bytes = new TextEncoder().encode(identity);
  const hex = Buffer.from(bytes).toString("hex");
  const lenWord = bytes.length.toString(16).padStart(64, "0");
  const padded = hex.padEnd(Math.ceil(hex.length / 64) * 64, "0");
  // 0x + selector(8) + offset(64=0x20) + length(64) + data
  const offsetWord = (32).toString(16).padStart(64, "0");
  return "0x00000000" + offsetWord + lenWord + padded;
}

/**
 * Decode a 32-byte-word eth_call result into a checksum-less lowercase address
 * (last 20 bytes of the last 32-byte word). Returns null on any malformed
 * result. Never throws.
 */
function decodeAddressResult(result: string): string | null {
  const hex = result.startsWith("0x") ? result.slice(2) : result;
  if (hex.length < 64) return null;
  if (!/^[0-9a-fA-F]+$/.test(hex)) return null;
  const lastWord = hex.slice(hex.length - 64);
  const addr = "0x" + lastWord.slice(24);
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return null;
  // All-zero address is "not registered", not a match.
  if (/^0x0{40}$/.test(addr)) return null;
  return addr;
}

// ── MCP tool definition ──────────────────────────────────────────────

export interface Erc8004ResolveToolsOptions {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  /**
   * Operator-supplied registry RPC endpoint (DEFAULT-OFF). When omitted the
   * resolve tool does offline verification only and never egresses.
   */
  rpcEndpoint?: string;
  allowPrivateRpc?: boolean;
}

export function createErc8004ResolveTools(
  opts: Erc8004ResolveToolsOptions,
): { tools: ToolDefinition[] } {
  const tools: ToolDefinition[] = [
    {
      name: "sanctuary/resolve_erc8004_identity",
      tool_class: "read",
      description:
        "Resolve and verify a presented ERC-8004 agent-identity record. " +
        "By default this is an OFFLINE, read-only check: it recomputes the " +
        "record's signature against the embedded signer address and returns " +
        "valid/invalid plus the verified identity fields. A valid result " +
        "proves only that the record carries a self-consistent secp256k1 " +
        "signature recoverable to its signer address; it does NOT prove the " +
        "signer is the registry's recorded owner unless the operator has " +
        "configured a registry RPC endpoint, in which case registry_confirmed " +
        "reports the on-chain check. No outbound request is made when no " +
        "endpoint is configured. Never returns key material.",
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
            ...(opts.rpcEndpoint !== undefined
              ? { rpcEndpoint: opts.rpcEndpoint }
              : {}),
            ...(opts.allowPrivateRpc !== undefined
              ? { allowPrivateRpc: opts.allowPrivateRpc }
              : {}),
          },
          (args as Record<string, unknown>).record,
        );
        return toolResult(result);
      },
    },
  ];

  return { tools };
}
