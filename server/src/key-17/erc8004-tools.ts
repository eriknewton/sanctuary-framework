/**
 * Key 17 -- ERC-8004 Identity Registry operator UX tools.
 *
 * MCP tool `sanctuary/sign_erc8004_identity` + shared service logic
 * for the CLI. Three-tier policy evaluation:
 *   Tier 1 (auto-approved) -> sign immediately, return signature
 *   Tier 2 (operator approval required) -> write inbox entry, return pending
 *   Tier 3 (denied by policy) -> return denied with reason
 *
 * Castle-walking: no outbound surface. Signature production is local;
 * on-chain broadcast is operator-side and out of scope.
 */

import { randomUUID } from "node:crypto";

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { UnifiedInboxBridge } from "../principal-policy/unified-inbox-bridge.js";
import {
  signErc8004Registration,
  type Erc8004Registration,
  type SignedErc8004Registration,
} from "./erc8004-identity-signer.js";
import {
  SigningDeniedError,
  type PolicyGate,
  type SigningApprovalRequest,
} from "./policy-gate.js";

// ── Audit ops ────────────────────────────────────────────────────────

export const ERC8004_AUDIT_OPS = {
  REQUESTED: "erc8004.identity.requested",
  PENDING_APPROVAL: "erc8004.identity.pending_approval",
  SIGNED: "erc8004.identity.signed",
  DENIED: "erc8004.identity.denied",
  DELETED_REQUEST: "erc8004.identity.deleted_request",
} as const;

// ── Pending request store (in-memory v1) ─────────────────────────────

export interface Erc8004PendingRequest {
  request_id: string;
  registration: Erc8004Registration;
  operator_id: string;
  master_key: Uint8Array;
  status: "pending_approval" | "signed" | "denied";
  result?: SignedErc8004Registration;
  deny_reason?: string;
  created_at: string;
  resolved_at?: string;
  inbox_id?: string;
}

export class Erc8004PendingStore {
  private readonly requests = new Map<string, Erc8004PendingRequest>();

  set(request: Erc8004PendingRequest): void {
    this.requests.set(request.request_id, request);
  }

  get(requestId: string): Erc8004PendingRequest | undefined {
    return this.requests.get(requestId);
  }

  delete(requestId: string): boolean {
    return this.requests.delete(requestId);
  }

  /** Visible for tests. */
  size(): number {
    return this.requests.size;
  }
}

// ── Shared service logic ─────────────────────────────────────────────

export interface Erc8004ToolResponse {
  request_id: string;
  status: "pending_approval" | "auto_approved" | "signed" | "denied";
  signature?: string;
  signer_address?: string;
  reason?: string;
}

export interface Erc8004ServiceDeps {
  masterKey: Uint8Array;
  operatorId: string;
  policyGate: PolicyGate;
  auditLog: AuditLog;
  identityId: string;
  pendingStore: Erc8004PendingStore;
  inboxBridge?: UnifiedInboxBridge;
  fortressId: string;
}

/**
 * Validate an EIP-55 checksummed Ethereum address (basic format check).
 */
export function isValidEthAddress(addr: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(addr);
}

/**
 * Execute an ERC-8004 Identity Registry signing request through the
 * three-tier policy gate.
 *
 * Structural guarantee: `policyGate.checkApproval()` is ALWAYS called
 * before `signErc8004Registration()` on every code path.
 */
export async function handleErc8004Request(
  deps: Erc8004ServiceDeps,
  registration: Erc8004Registration,
  opts?: { autoApprove?: boolean },
): Promise<Erc8004ToolResponse> {
  const requestId = randomUUID();
  const now = new Date().toISOString();

  // Audit: request received
  void deps.auditLog.append("l2", ERC8004_AUDIT_OPS.REQUESTED, deps.identityId, {
    request_id: requestId,
    registry: registration.registry,
    chain_id: registration.chain_id,
    identity: registration.identity,
    fortress_id: deps.fortressId,
  });

  const approvalRequest: SigningApprovalRequest = {
    protocol: "erc8004",
    operatorId: deps.operatorId,
    action: "sign_registration",
    counterparty: registration.registry,
    metadata: {
      identity: registration.identity,
      chain_id: registration.chain_id,
    },
  };

  // Approval is the last boundary before key use; no branch below may call the
  // signer unless this check allowed it or a pending request was approved later.
  try {
    await deps.policyGate.checkApproval(approvalRequest);
  } catch (e) {
    if (!(e instanceof SigningDeniedError)) throw e;

    const isApprovalRequired =
      e.reason.includes("approval required") ||
      e.reason.includes("approval channel") ||
      e.reason.includes("operator denied");

    if (isApprovalRequired && !opts?.autoApprove) {
      // Tier 2: operator approval required -- write inbox entry
      let inboxId: string | undefined;
      if (deps.inboxBridge) {
        const entry = deps.inboxBridge.ingestApproval({
          source_event_id: `erc8004:${requestId}`,
          severity: "alert",
          summary:
            `ERC-8004 Identity Registry registration requested for ` +
            `${registration.identity} on chain ${registration.chain_id} ` +
            `(registry ${registration.registry.slice(0, 10)}...)`,
          observed_at: now,
        });
        inboxId = entry?.inbox_id;
      }

      // The pending request keeps key material process-local only so a later
      // approval can sign the same payload without persisting the master key.
      deps.pendingStore.set({
        request_id: requestId,
        registration,
        operator_id: deps.operatorId,
        master_key: deps.masterKey,
        status: "pending_approval",
        created_at: now,
        inbox_id: inboxId,
      });

      await deps.auditLog.append(
        "l2",
        ERC8004_AUDIT_OPS.PENDING_APPROVAL,
        deps.identityId,
        {
          request_id: requestId,
          registry: registration.registry,
          chain_id: registration.chain_id,
          identity: registration.identity,
          inbox_id: inboxId,
          fortress_id: deps.fortressId,
        },
      );

      return { request_id: requestId, status: "pending_approval" };
    }

    if (isApprovalRequired && opts?.autoApprove) {
      // Operator pre-confirmed via CLI --auto-approve; proceed to sign
      // (fall through to signing below)
    } else {
      // Tier 3: denied by policy
      await deps.auditLog.append(
        "l2",
        ERC8004_AUDIT_OPS.DENIED,
        deps.identityId,
        {
          request_id: requestId,
          registry: registration.registry,
          chain_id: registration.chain_id,
          reason: e.reason,
          fortress_id: deps.fortressId,
        },
      );

      return { request_id: requestId, status: "denied", reason: e.reason };
    }
  }

  // Tier 1 auto-approved (or CLI pre-confirmed): sign only after the policy
  // decision path above has settled in favor of this exact registration.
  const signed = signErc8004Registration(
    deps.masterKey,
    deps.operatorId,
    registration,
  );

  deps.policyGate.emitAuditEvent({
    protocol: "erc8004",
    operatorId: deps.operatorId,
    action: "sign_registration",
    counterparty: registration.registry,
    success: true,
  });

  await deps.auditLog.append("l2", ERC8004_AUDIT_OPS.SIGNED, deps.identityId, {
    request_id: requestId,
    registry: registration.registry,
    chain_id: registration.chain_id,
    identity: registration.identity,
    signer_address: signed.signer_address,
    fortress_id: deps.fortressId,
  });

  return {
    request_id: requestId,
    status: "signed",
    signature: signed.signature,
    signer_address: signed.signer_address,
  };
}

/**
 * Resolve a pending ERC-8004 request (called from inbox approve callback).
 */
export async function resolvePendingRequest(
  pendingStore: Erc8004PendingStore,
  auditLog: AuditLog,
  identityId: string,
  requestId: string,
  approved: boolean,
  fortressId: string,
  reason?: string,
): Promise<Erc8004ToolResponse | null> {
  const pending = pendingStore.get(requestId);
  if (!pending || pending.status !== "pending_approval") return null;

  const now = new Date().toISOString();

  if (!approved) {
    pending.status = "denied";
    pending.deny_reason = reason ?? "operator denied";
    pending.resolved_at = now;
    pendingStore.set(pending);

    await auditLog.append("l2", ERC8004_AUDIT_OPS.DENIED, identityId, {
      request_id: requestId,
      reason: pending.deny_reason,
      fortress_id: fortressId,
    });

    return {
      request_id: requestId,
      status: "denied",
      reason: pending.deny_reason,
    };
  }

  // The inbox approval is the delayed authority boundary; only an approved,
  // still-pending request may reach the signer.
  const signed = signErc8004Registration(
    pending.master_key,
    pending.operator_id,
    pending.registration,
  );

  pending.status = "signed";
  pending.result = signed;
  pending.resolved_at = now;
  pendingStore.set(pending);

  await auditLog.append("l2", ERC8004_AUDIT_OPS.SIGNED, identityId, {
    request_id: requestId,
    registry: pending.registration.registry,
    chain_id: pending.registration.chain_id,
    identity: pending.registration.identity,
    signer_address: signed.signer_address,
    fortress_id: fortressId,
  });

  return {
    request_id: requestId,
    status: "signed",
    signature: signed.signature,
    signer_address: signed.signer_address,
  };
}

// ── MCP tool definitions ─────────────────────────────────────────────

export interface Erc8004ToolsOptions {
  masterKey: Uint8Array;
  policyGate: PolicyGate;
  auditLog: AuditLog;
  identityId: string;
  operatorId: string;
  inboxBridge?: UnifiedInboxBridge;
  fortressId: string;
}

export function createErc8004Tools(
  opts: Erc8004ToolsOptions,
): { tools: ToolDefinition[]; pendingStore: Erc8004PendingStore } {
  const pendingStore = new Erc8004PendingStore();

  const tools: ToolDefinition[] = [
    {
      name: "sanctuary/sign_erc8004_identity",
      description:
        "Request an ERC-8004 Identity Registry registration signature. " +
        "The request flows through the three-tier policy gate: pre-approved " +
        "counterparties get an immediate signature; others require operator " +
        "approval via the inbox. No on-chain broadcast; the caller submits " +
        "the returned signature to the registry contract.",
      inputSchema: {
        type: "object",
        properties: {
          registry_address: {
            type: "string",
            description:
              "EIP-55 checksummed Ethereum address of the Identity Registry contract.",
          },
          chain_id: {
            type: "number",
            description: "Chain ID (1 = mainnet; testnets allowed).",
          },
          agent_id: {
            type: "string",
            description: "Canonical agent identifier to register.",
          },
          nonce: {
            type: "number",
            description: "Anti-replay nonce from the registry contract.",
          },
          metadata_uri: {
            type: "string",
            description:
              "Optional IPFS or HTTPS URI for off-chain agent metadata.",
          },
          counterparty: {
            type: "string",
            description:
              "Optional counterparty agent id for policy-gate matching.",
          },
          request_id: {
            type: "string",
            description:
              "If provided, check the status of an existing request instead " +
              "of creating a new one (poll pattern).",
          },
        },
        required: ["registry_address", "chain_id", "agent_id", "nonce"],
      },
      handler: async (args) => {
        // Poll mode: check existing request
        if (args.request_id && typeof args.request_id === "string") {
          const pending = pendingStore.get(args.request_id);
          if (!pending) {
            return toolResult({
              error: "unknown_request_id",
              message: `No pending request found for ${args.request_id}`,
            });
          }
          if (pending.status === "signed" && pending.result) {
            return toolResult({
              request_id: pending.request_id,
              status: "signed",
              signature: pending.result.signature,
              signer_address: pending.result.signer_address,
            });
          }
          return toolResult({
            request_id: pending.request_id,
            status: pending.status,
            ...(pending.deny_reason
              ? { reason: pending.deny_reason }
              : {}),
          });
        }

        // Validate inputs
        const registryAddress = args.registry_address as string;
        const chainId = args.chain_id as number;
        const agentId = args.agent_id as string;
        const nonce = args.nonce as number;
        const metadataUri = args.metadata_uri as string | undefined;

        if (!isValidEthAddress(registryAddress)) {
          return toolResult({
            error: "invalid_registry_address",
            message:
              "registry_address must be a valid EIP-55 Ethereum address (0x + 40 hex chars).",
          });
        }

        if (
          !Number.isFinite(chainId) ||
          chainId < 1 ||
          !Number.isInteger(chainId)
        ) {
          return toolResult({
            error: "invalid_chain_id",
            message: "chain_id must be a positive integer.",
          });
        }

        if (!agentId || agentId.trim().length === 0) {
          return toolResult({
            error: "invalid_agent_id",
            message: "agent_id is required and must be non-empty.",
          });
        }

        // The registry nonce is signed into the registration, so malformed
        // nonces are refused before they can become durable signature input.
        if (
          !Number.isFinite(nonce) ||
          nonce < 0 ||
          !Number.isInteger(nonce)
        ) {
          return toolResult({
            error: "invalid_nonce",
            message: "nonce must be a non-negative integer.",
          });
        }

        const registration: Erc8004Registration = {
          identity: agentId,
          registry: registryAddress,
          chain_id: chainId,
          nonce,
          timestamp: new Date().toISOString(),
          ...(metadataUri !== undefined ? { metadata_uri: metadataUri } : {}),
        };

        const result = await handleErc8004Request(
          {
            masterKey: opts.masterKey,
            operatorId: opts.operatorId,
            policyGate: opts.policyGate,
            auditLog: opts.auditLog,
            identityId: opts.identityId,
            pendingStore,
            inboxBridge: opts.inboxBridge,
            fortressId: opts.fortressId,
          },
          registration,
        );

        return toolResult(result);
      },
    },
  ];

  return { tools, pendingStore };
}
