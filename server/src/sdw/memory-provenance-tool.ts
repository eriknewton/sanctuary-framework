/**
 * SDW memory provenance MCP tool: `sdw_memory_provenance`.
 *
 * Returns the per-record provenance the shipped machinery carries. C2 rows
 * expose a verified fortress-recorded origin/admission binding; legacy rows
 * remain explicitly unsigned in PRE_MIGRATION. A valid signature proves only
 * that the resolved fortress key signed the exact origin/admission bytes; it
 * does not prove true authorship, content truth, safety, or a remote identity.
 *
 * PUBLIC-SAFE PROJECTION (MUST-NEVER #7): the response carries only the
 * passage's own bounded provenance. It does NOT leak signatures, key bytes,
 * redacted audit internals, policy detail, or the passage body. Failures return
 * the fixed-denial schema; details go to the audit log only.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import { fixedDenial } from "../agent-native/safety-base.js";
import type { MemoryBackendAdapter, MemoryPassage } from "./adapters/memory-backend.js";
import { SdwValidationError } from "./errors.js";
import type { MultiAgentIsolationGuard } from "./memory-isolation.js";
import { SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS } from "./memory-tools.js";
import type { MemoryProvenanceCompanion } from "./memory-provenance-contract.js";

export interface SdwMemoryProvenanceToolOptions {
  /** The shipped sovereign passage backend, scoped to one owner_ref. */
  readonly adapter: MemoryBackendAdapter;
  readonly auditLog: AuditLog;
  /**
   * The SAME guard instance as every other family over the shared scope
   * (index.ts). Provenance reads reveal passage existence, owner ref, hashes
   * and tags, so a second wrapped-agent identity is refused here too.
   */
  readonly isolationGuard?: MultiAgentIsolationGuard;
}

/** Stable bounded projection of verified binding facts and legacy gaps. */
function provenanceGaps(
  status: "verified" | "unsigned",
  companion?: MemoryProvenanceCompanion,
): Record<string, unknown> {
  if (status === "verified") {
    if (companion === undefined) throw new Error("verified memory provenance companion missing");
    const origin = companion.origin.body;
    const admission = companion.admission.body;
    return {
      per_writer_signature: "verified",
      signing_status: "verified",
      ingress_channel: origin.ingress_channel,
      source_class: origin.source_class,
      recorded_at: origin.recorded_at,
      admission_channel: admission.admission_channel,
      origin_trust_tier: admission.origin_trust_tier,
      verification_basis: admission.verification_basis,
      admitted_at: admission.admitted_at,
      taint_retrievable: false,
      automatic_provenance_event: true,
      note: "The fortress-recorded origin and admission bindings verify for this exact passage. This does not prove true authorship, content truth, safety, or a remote identity.",
    };
  }
  return {
    // PRE_MIGRATION legacy compatibility: no companion was attached.
    per_writer_signature: null,
    signing_status: "not_bound",
    // The persistable taint is enforced by the write-gate at write time but is
    // not stored retrievably on the passage, so it cannot be reported here.
    taint_retrievable: false,
    // PRE_MIGRATION legacy rows predate automatic C2 companion attachment.
    automatic_provenance_event: false,
    note:
      "Tamper-evidence today is the re-verified content hash. Per-writer signer " +
      "identity and retrievable taint are not bound on this PRE_MIGRATION legacy row.",
  };
}

function sameProvenanceSnapshot(
  first: Awaited<ReturnType<MemoryBackendAdapter["getPassageProvenance"]>>,
  second: Awaited<ReturnType<MemoryBackendAdapter["getPassageProvenance"]>>,
): boolean {
  if (first.status !== second.status) return false;
  if (first.status !== "verified" || second.status !== "verified") return true;
  return JSON.stringify(first.companion) === JSON.stringify(second.companion);
}

function companionBindsPublicPassage(
  companion: MemoryProvenanceCompanion,
  passage: MemoryPassage,
): boolean {
  const origin = companion.origin.body;
  const admission = companion.admission.body;
  return origin.passage_id === passage.passage_id &&
    origin.owner_ref === passage.owner_ref &&
    origin.content_hash === passage.content_hash &&
    origin.chunk_count === passage.chunk_count &&
    admission.passage_id === passage.passage_id &&
    admission.destination_owner_ref === passage.owner_ref;
}

/**
 * Audit operation catalog for this tool. Every `appendCritical` here names its
 * operation through this table (never a string literal) so the wired-consumer
 * test in test/sdw/memory-provenance-tool.test.ts and the tool agree on one
 * source; a test pinned to the same constants cannot drift from the code.
 */
export const SDW_MEMORY_PROVENANCE_AUDIT_OPS = {
  /** One record per successful provenance read (found or not found). */
  read: "sdw_memory_provenance_read",
  /** Denial paths: invalid passage id, integrity failure, backend failure. */
  denied: "sdw_memory_provenance_denied",
} as const;

export function createSdwMemoryProvenanceTool(
  options: SdwMemoryProvenanceToolOptions,
): ToolDefinition {
  const { adapter, auditLog } = options;

  const auditFailure = (details: Record<string, unknown>): Promise<void> =>
    auditLog.appendCritical({
      layer: "l1",
      operation: SDW_MEMORY_PROVENANCE_AUDIT_OPS.denied,
      identity_id: "system",
      result: "failure",
      details,
    });

  // Provenance inspection is as sensitive as the read it judges: a successful
  // read leaves exactly one durable record (IC-28), written BEFORE the answer
  // is returned so a downed audit sink denies rather than answers unlogged
  // (audit-before-return, MUST-NEVER #5). Details carry the passage id and
  // whether it was found; never the passage body.
  const auditRead = (details: { passage_id: string; found: boolean }): Promise<void> =>
    auditLog.appendCritical({
      layer: "l1",
      operation: SDW_MEMORY_PROVENANCE_AUDIT_OPS.read,
      identity_id: "principal",
      result: "success",
      details,
    });

  const deny = () =>
    toolResult(fixedDenial("audit:sdw_memory_provenance", "request_review", null));

  const refusedForeignIdentity = async (): Promise<boolean> => {
    if (options.isolationGuard === undefined) return false;
    if (options.isolationGuard("sdw_memory_provenance").allowed) return false;
    await auditFailure({ denial_class: SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS });
    return true;
  };

  return {
    name: "sdw_memory_provenance",
    description:
      "Show per-record SDW memory integrity status. Verified rows expose the " +
      "bounded fortress-recorded origin/admission classes; unsigned PRE_MIGRATION " +
      "rows are explicit. Verification does not prove true authorship, content " +
      "truth, safety, or a remote identity.",
    tool_class: "read",
    inputSchema: {
      type: "object",
      properties: {
        passage_id: {
          type: "string",
          description: "Passage id to inspect provenance for",
        },
      },
      required: ["passage_id"],
    },
    // Gate-time projection: the shared isolation guard runs BEFORE the
    // approval gate sees the call, so a foreign identity never reaches a
    // prompt or a Tier decision; the throw makes the router deny without
    // prompting. The projection carries only the passage id (no body exists
    // on this read tool).
    approvalTargetArgs: async (args) => {
      if (await refusedForeignIdentity()) {
        throw new SdwValidationError(
          "owner_scope_conflict",
          "sdw_memory_provenance refused for a second wrapped-agent identity",
        );
      }
      return { passage_id: args.passage_id };
    },
    handler: async (args) => {
      // Handler recheck (the gate-time projection above already refused a
      // foreign identity before the approval gate; this keeps the handler
      // safe when invoked without the router).
      if (await refusedForeignIdentity()) return deny();
      const passageId = args.passage_id;
      if (typeof passageId !== "string" || passageId.length === 0) {
        await auditFailure({ denial_class: "invalid_passage_id" });
        return deny();
      }
      try {
        const recordProvenance = await adapter.getPassageProvenance(passageId);
        if (recordProvenance.status === "unresolved") {
          await auditRead({ passage_id: passageId, found: false });
          return toolResult({ found: false, provenance_status: "unresolved" });
        }
        if (recordProvenance.status === "quarantined") {
          await auditRead({ passage_id: passageId, found: true });
          return toolResult({ found: true, provenance_status: "quarantined" });
        }
        const passage = await adapter.getPassage(passageId);
        if (passage === null) throw new Error("passage disappeared during provenance inspection");
        const confirmedProvenance = await adapter.getPassageProvenance(passageId);
        if (!sameProvenanceSnapshot(recordProvenance, confirmedProvenance) ||
            (recordProvenance.status === "verified" &&
              !companionBindsPublicPassage(recordProvenance.companion, passage))) {
          throw new SdwValidationError(
            "auth_failed",
            "SDW memory passage changed during provenance inspection; retry",
          );
        }
        await auditRead({ passage_id: passageId, found: true });
        // Public-safe provenance: the passage's own non-sensitive facts plus
        // the honest gaps block. No body text, no audit internals, no ids
        // beyond the caller's own passage/owner refs.
        return toolResult({
          found: true,
          provenance_status: recordProvenance.status,
          provenance: {
            passage_id: passage.passage_id,
            owner_ref: passage.owner_ref,
            content_hash: passage.content_hash,
            content_hash_verified_on_read: true,
            created_at: passage.created_at,
            chunk_count: passage.chunk_count,
            tags: [...passage.tags],
          },
          provenance_gaps: provenanceGaps(
            recordProvenance.status,
            recordProvenance.status === "verified" ? recordProvenance.companion : undefined,
          ),
        });
      } catch (error) {
        const category = error instanceof SdwValidationError ? error.category : "provenance_failed";
        await auditFailure({ denial_class: category });
        return deny();
      }
    },
  };
}
