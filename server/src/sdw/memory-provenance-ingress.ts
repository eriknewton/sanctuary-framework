/**
 * Slice C2 code-owned ingress authority.
 *
 * The exported values are opaque capabilities. Their claims live only in this
 * module's WeakMap, so a caller cannot forge an ingress/source pair with an
 * object literal or mutate a genuine context after it is minted.
 */
import type {
  MemoryAdmissionChannel,
  MemoryIngressChannel,
  MemoryOriginTrustTier,
  MemorySourceClass,
  MemoryVerificationBasis,
} from "./memory-provenance-contract.js";

declare const INGRESS_CONTEXT: unique symbol;
export interface MemoryProvenanceIngressContext {
  readonly [INGRESS_CONTEXT]: true;
}

export interface ResolvedMemoryProvenanceIngress {
  readonly author_agent_id: string;
  readonly ingress_channel: Exclude<MemoryIngressChannel, "legacy_migration" | "fleet_sync" | "disclosure_capsule_return">;
  readonly source_class: Exclude<MemorySourceClass, "fleet_sync_lineage" | "provider_return_locally_observed" | "tool_return_locally_observed" | "peer_return_signed">;
  readonly admission_channel: MemoryAdmissionChannel;
  readonly origin_trust_tier: MemoryOriginTrustTier;
  readonly verification_basis: MemoryVerificationBasis;
  readonly transfer_lineage_ref?: string;
}

const contexts = new WeakMap<object, ResolvedMemoryProvenanceIngress>();

function mint(value: Omit<ResolvedMemoryProvenanceIngress, "admission_channel" | "origin_trust_tier" | "verification_basis"> &
  Partial<Pick<ResolvedMemoryProvenanceIngress, "admission_channel" | "origin_trust_tier" | "verification_basis">>): MemoryProvenanceIngressContext {
  const token = Object.freeze(Object.create(null)) as MemoryProvenanceIngressContext;
  contexts.set(token, Object.freeze({
    admission_channel: "local_write",
    origin_trust_tier: "local_attested",
    verification_basis: "local_primary_identity",
    ...value,
  }) as ResolvedMemoryProvenanceIngress);
  return token;
}

function requireAuthor(value: string): string {
  if (value.length < 1 || value.length > 256) throw new Error("Invalid memory provenance author agent id");
  return value;
}

export type CurrentMemoryAgentId = () => string | undefined;

/**
 * Snapshot the same code-owned wrapped-agent identity used by the isolation
 * guard. The resolver is invoked exactly once while the opaque capability is
 * minted; later environment changes cannot rewrite an in-flight origin.
 */
function localCallerAuthor(currentAgentId: CurrentMemoryAgentId | undefined): string {
  const observed = currentAgentId?.();
  return requireAuthor(observed === undefined || observed.length === 0 ? "unknown_local" : observed);
}

export function memoryInsertIngress(
  currentAgentId: CurrentMemoryAgentId | undefined,
  sourceClass: "user_content" | "agent_derived_clean" | "system_generated",
): MemoryProvenanceIngressContext {
  return mint({ author_agent_id: localCallerAuthor(currentAgentId), ingress_channel: "memory_insert", source_class: sourceClass });
}

export function anthropicMemoryToolIngress(
  currentAgentId: CurrentMemoryAgentId | undefined,
  sourceClass: "user_content" | "agent_derived_clean" | "system_generated",
): MemoryProvenanceIngressContext {
  return mint({ author_agent_id: localCallerAuthor(currentAgentId), ingress_channel: "anthropic_memory_tool", source_class: sourceClass });
}

export function fileImportIngress(
  authorAgentId: string,
  sourceClass: "claude_code_index" | "claude_code_fact" | "codex_index" | "codex_summary" | "codex_raw",
): MemoryProvenanceIngressContext {
  return mint({ author_agent_id: requireAuthor(authorAgentId), ingress_channel: "file_import", source_class: sourceClass });
}

export function memoryTranscodeIngress(
  authorAgentId: string,
  sourceClass: "transcode_manifest" | "transcode_source_file" | "exit_lineage",
): MemoryProvenanceIngressContext {
  return mint({ author_agent_id: requireAuthor(authorAgentId), ingress_channel: "memory_transcode", source_class: sourceClass });
}

/** Existing Exit V1 material is legacy-unattested at the destination. */
export function legacyExitV1ImportIngress(transferLineageRef: string): MemoryProvenanceIngressContext {
  return mint({
    author_agent_id: "unknown_legacy",
    ingress_channel: "legacy_unknown",
    source_class: "legacy_unattested",
    admission_channel: "exit_v2_import",
    origin_trust_tier: "legacy_unattested",
    verification_basis: "exit_v2_legacy_v1",
    transfer_lineage_ref: transferLineageRef,
  });
}

export function resolveMemoryProvenanceIngress(
  context: MemoryProvenanceIngressContext,
): ResolvedMemoryProvenanceIngress | undefined {
  return contexts.get(context);
}
