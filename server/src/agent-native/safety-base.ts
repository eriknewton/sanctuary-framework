import { createHash, randomBytes } from "node:crypto";
import type { AuditLog } from "../operational/audit-log.js";
import type { ToolDefinition } from "../router.js";
import { decodeExportBundleNamespaces } from "../cognitive/state-store.js";
import {
  normalizeToolArgsForValidation,
  ToolArgumentValidationError,
} from "../tool-args.js";
import { COOPERATIVE_TOOL_NAMES } from "./tool-names.js";

export type RiskTier = 1 | 2 | 3;
export type RemediationClass =
  | "request_review"
  | "try_lower_scope"
  | "unavailable"
  | "wait";
export type RetryAfterBucket = null | "later" | "minutes" | "hours";

export interface FixedDenial {
  denied: true;
  message: "This action is not available in the current context.";
  remediation_class: RemediationClass;
  retry_after: RetryAfterBucket;
  audit_ref: string;
  /**
   * Static, invariant discovery pointer (never parameterized). Same on every
   * denial so it cannot leak tier/rule/attempt; see
   * COOPERATIVE_DENIAL_DISCOVERY_HINT.
   */
  discovery_hint: typeof COOPERATIVE_DENIAL_DISCOVERY_HINT;
}

export const FIXED_DENIAL_MESSAGE =
  "This action is not available in the current context." as const;

/**
 * Static discovery pointer attached to every cooperative denial
 * (enforcement-as-teacher, harness-agnostic non-wall part; design Section 5
 * move 3).
 *
 * SAFETY (AGENTS.md hard rule 7 - no-policy-inference): this string is a
 * compile-time CONSTANT and is IDENTICAL on every denial, regardless of which
 * tool, tier, or rule produced it. It names only the general discovery
 * entrypoints (sanctuary_help / sanctuary_capabilities), never a per-request
 * tool. It therefore cannot leak which tier/rule fired or what the caller
 * attempted: the field is byte-for-byte the same on every denial. It teaches
 * "where to look" without revealing "what tripped". Do NOT parameterize this
 * by intent, tool, or denial reason.
 */
export const COOPERATIVE_DENIAL_DISCOVERY_HINT =
  `To find the sanctioned Sanctuary tool for what you need, call ${COOPERATIVE_TOOL_NAMES.help} with your intent, or ${COOPERATIVE_TOOL_NAMES.capabilities} for the full catalog.` as const;

export function fixedDenial(
  auditRef: string,
  remediationClass: RemediationClass = "request_review",
  retryAfter: RetryAfterBucket = null
): FixedDenial {
  return {
    denied: true,
    message: FIXED_DENIAL_MESSAGE,
    remediation_class: remediationClass,
    retry_after: retryAfter,
    audit_ref: auditRef,
    discovery_hint: COOPERATIVE_DENIAL_DISCOVERY_HINT,
  };
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

export function sha256(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function normalizedArgsHash(args: Record<string, unknown>): `sha256:${string}` {
  return sha256(canonicalJson(args));
}

export interface CanonicalApprovalEnvelope {
  tool_name: string;
  normalized_args_hash: `sha256:${string}`;
  requester_identity_fingerprint: `sha256:${string}`;
  target_resource: string;
  risk_tier: RiskTier;
  plan_hash?: `sha256:${string}`;
  step_id?: string;
  expires_at: string;
  nonce: string;
  audit_id: string;
}

export function approvalEnvelopeHash(
  envelope: CanonicalApprovalEnvelope
): `sha256:${string}` {
  return sha256(canonicalJson(envelope));
}

export interface ApprovalRecord {
  approval_ref: string;
  envelope: CanonicalApprovalEnvelope;
  envelope_hash: `sha256:${string}`;
  decision: "approved" | "denied";
  consumed: boolean;
  reserved_by?: string;
  created_at: string;
}

export class ApprovalProofStore {
  private records = new Map<string, ApprovalRecord>();

  createApproved(envelope: CanonicalApprovalEnvelope): ApprovalRecord {
    const record: ApprovalRecord = {
      approval_ref: `approval:${randomBytes(16).toString("hex")}`,
      envelope,
      envelope_hash: approvalEnvelopeHash(envelope),
      decision: "approved",
      consumed: false,
      created_at: new Date().toISOString(),
    };
    this.records.set(record.approval_ref, record);
    return record;
  }

  get(approvalRef: string): ApprovalRecord | undefined {
    return this.records.get(approvalRef);
  }

  reserveIfUnconsumed(approvalRef: string, reservationId: string): ApprovalRecord | null {
    const record = this.records.get(approvalRef);
    if (!record || record.consumed || record.reserved_by) return null;
    record.reserved_by = reservationId;
    return record;
  }

  releaseReservation(approvalRef: string, reservationId: string): boolean {
    const record = this.records.get(approvalRef);
    if (!record || record.reserved_by !== reservationId || record.consumed) return false;
    delete record.reserved_by;
    return true;
  }

  consumeReserved(approvalRef: string, reservationId: string): ApprovalRecord | null {
    const record = this.records.get(approvalRef);
    if (!record || record.consumed || record.reserved_by !== reservationId) return null;
    record.consumed = true;
    delete record.reserved_by;
    return record;
  }

  consumeIfUnconsumed(approvalRef: string): ApprovalRecord | null {
    const record = this.records.get(approvalRef);
    if (!record || record.consumed || record.reserved_by) return null;
    record.consumed = true;
    return record;
  }
}

export interface SessionBinding {
  identity_id?: string;
  requester_identity_fingerprint?: `sha256:${string}`;
  expires_at?: string;
  delegated_scopes?: string[];
}

export interface ActiveSessionIdentity {
  identity_id: string;
  requester_identity_fingerprint: `sha256:${string}`;
}

export class SessionIdentityError extends Error {
  constructor(message = FIXED_DENIAL_MESSAGE) {
    super(message);
    this.name = "SessionIdentityError";
  }
}

export function fingerprintIdentityId(identityId: string): `sha256:${string}` {
  return sha256(`identity:${identityId}`);
}

export function resolveActiveSessionIdentity(
  binding: SessionBinding | undefined
): ActiveSessionIdentity {
  if (!binding?.identity_id || !binding.requester_identity_fingerprint) {
    throw new SessionIdentityError();
  }
  if (binding.expires_at && Date.parse(binding.expires_at) <= Date.now()) {
    throw new SessionIdentityError();
  }
  if (
    binding.requester_identity_fingerprint !==
    fingerprintIdentityId(binding.identity_id)
  ) {
    throw new SessionIdentityError();
  }
  return {
    identity_id: binding.identity_id,
    requester_identity_fingerprint: binding.requester_identity_fingerprint,
  };
}

export class OpaqueNamespaceRegistry {
  private handleToIdentity = new Map<string, string>();
  private identityToHandle = new Map<string, string>();

  issueMemoryHandle(identityId: string): string {
    const existing = this.identityToHandle.get(identityId);
    if (existing) return existing;
    const handle = `mem_${randomBytes(16).toString("hex")}`;
    this.identityToHandle.set(identityId, handle);
    this.handleToIdentity.set(handle, identityId);
    return handle;
  }

  isOpaqueMemoryHandle(namespace: string): boolean {
    return namespace.startsWith("mem_");
  }

  getOwner(namespace: string): string | undefined {
    return this.handleToIdentity.get(namespace);
  }

  getHandleForIdentity(identityId: string): string | undefined {
    return this.identityToHandle.get(identityId);
  }

  assertOwned(namespace: string, binding: SessionBinding | undefined): void {
    if (!this.isOpaqueMemoryHandle(namespace)) return;
    const active = resolveActiveSessionIdentity(binding);
    if (this.handleToIdentity.get(namespace) !== active.identity_id) {
      throw new SessionIdentityError();
    }
  }
}

export interface ApprovalPreflightResult {
  tool_name: string;
  normalized_args_hash: `sha256:${string}`;
  requester_identity_fingerprint: `sha256:${string}`;
  target_resource: string;
  risk_tier: RiskTier;
  audit_id: string;
}

export function deriveTargetResource(
  toolName: string,
  args: Record<string, unknown>
): string {
  const namespace = typeof args.namespace === "string" ? args.namespace : "";
  const key = typeof args.key === "string" ? args.key : "";
  const bundleNamespaces =
    toolName === "state_import" && typeof args.bundle === "string"
      ? decodeStateBundleNamespaces(args.bundle)
      : [];
  const namespaces =
    Array.isArray(args.namespaces) && args.namespaces.every((ns) => typeof ns === "string")
      ? [...args.namespaces].sort()
      : bundleNamespaces;
  if (namespace && key) return `${toolName}:${namespace}/${key}`;
  if (namespace) return `${toolName}:${namespace}`;
  if (namespaces.length > 0) return `${toolName}:${namespaces.join(",")}`;
  return toolName;
}

export function decodeStateBundleNamespaces(bundleBase64: string): string[] {
  return decodeExportBundleNamespaces(bundleBase64);
}

export async function classifyApprovalRequest(params: {
  operation: string;
  args: Record<string, unknown>;
  session: SessionBinding | undefined;
  tools: ToolDefinition[];
  classifyTier: (toolName: string, args: Record<string, unknown>) => RiskTier;
  auditLog: AuditLog;
}): Promise<ApprovalPreflightResult> {
  const tool = params.tools.find((t) => t.name === params.operation);
  if (!tool) {
    throw new Error(FIXED_DENIAL_MESSAGE);
  }
  let handlerArgs: Record<string, unknown>;
  try {
    ({ handlerArgs } = normalizeToolArgsForValidation({
      args: params.args,
      schema: tool.inputSchema,
      toolClass: tool.tool_class,
    }));
  } catch (error) {
    if (error instanceof ToolArgumentValidationError) {
      // SECURITY: do NOT attach `error` as the thrown error's `cause`. The
      // FIXED_DENIAL_MESSAGE is a fixed, generic denial by design (no-policy-
      // inference invariant): denials must not reveal which rule, tier, or
      // validation path triggered them. Threading the original
      // ToolArgumentValidationError through `cause` would leak that internal
      // detail to an agent-reachable surface, so the cause is deliberately
      // dropped here.
      // eslint-disable-next-line preserve-caught-error -- intentional: see SECURITY note above
      throw new Error(FIXED_DENIAL_MESSAGE);
    }
    throw error;
  }
  try {
    handlerArgs = (await tool.approvalTargetArgs?.(handlerArgs)) ?? handlerArgs;
  } catch {
    throw new Error(FIXED_DENIAL_MESSAGE);
  }
  const approvalToolName = tool.approvalTargetToolName ?? params.operation;
  const active = resolveActiveSessionIdentity(params.session);
  const riskTier = params.classifyTier(approvalToolName, handlerArgs);
  const auditId = `audit:approval_request:${randomBytes(12).toString("hex")}`;
  const argsHash = normalizedArgsHash(handlerArgs);
  let targetResource: string;
  try {
    targetResource = deriveTargetResource(approvalToolName, handlerArgs);
  } catch {
    throw new Error(FIXED_DENIAL_MESSAGE);
  }
  await params.auditLog.appendCritical({
    layer: "l2",
    operation: `approval_preflight:${params.operation}`,
    identity_id: active.identity_id,
    result: "success",
    details: {
      audit_id: auditId,
      tool_name: approvalToolName,
      normalized_args_hash: argsHash,
      target_resource: targetResource,
      risk_tier: riskTier,
    },
  });
  return {
    tool_name: approvalToolName,
    normalized_args_hash: argsHash,
    requester_identity_fingerprint: active.requester_identity_fingerprint,
    target_resource: targetResource,
    risk_tier: riskTier,
    audit_id: auditId,
  };
}
