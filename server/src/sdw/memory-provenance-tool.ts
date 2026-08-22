/**
 * SDW memory provenance MCP tool: `sdw_memory_provenance`.
 *
 * Returns the provenance that the SHIPPED machinery actually carries for a
 * stored passage, and HONESTLY reports what it does NOT yet carry. This is the
 * read-time-provenance SEAM for the memory-poisoning controls (the per-writer
 * signing + trust-tier + promotion design), not a claim that authorship is
 * already cryptographically proven.
 *
 * NEVER-OVERCLAIM (the load-bearing design constraint): the shipped
 * `MemoryPassage` surface carries `passage_id` / `owner_ref` / `content_hash`
 * / `created_at` / `chunk_count`. It does NOT carry a per-writer signature, and
 * the persistable taint asserted at write time is consumed by the write-gate
 * but is NOT stored retrievably on the passage. A passage insert also does not
 * automatically append a signer-bound audit/query-history record today (the
 * pre-existing optional `memory_attest` tool is manual after-the-fact
 * attestation, not automatic passage provenance). So this tool reports:
 *   - what IS provable today: the entry exists, its content hash, and that the
 *     content hash is re-verified on read (fail closed on mismatch);
 *   - what is NOT bound today: per-writer signing, a retrievable taint, an
 *     automatic provenance event - each surfaced as an explicit field so a
 *     reader is never misled into trusting unproven authorship.
 *
 * This is the never-overclaim ethos applied to the tool itself: the CISO value
 * is tamper-EVIDENCE of what we actually record, plus an honest map of the gap
 * the future per-writer-signing control fills.
 *
 * PUBLIC-SAFE PROJECTION (MUST-NEVER #7): the response carries only the
 * passage's own non-sensitive provenance. It does NOT leak redacted audit
 * internals, identity ids, policy detail, or the passage body. Failures return
 * the fixed-denial schema; details go to the audit log only.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import { fixedDenial } from "../agent-native/safety-base.js";
import type { MemoryBackendAdapter } from "./adapters/memory-backend.js";
import { SdwValidationError } from "./errors.js";

export interface SdwMemoryProvenanceToolOptions {
  /** The shipped sovereign passage backend, scoped to one owner_ref. */
  readonly adapter: MemoryBackendAdapter;
  readonly auditLog: AuditLog;
}

/**
 * The honest "what is NOT bound yet" block. Stable shape so the future
 * per-writer-signing control populates these fields rather than the reader
 * silently assuming authorship is proven.
 */
function provenanceGaps(): Record<string, unknown> {
  return {
    // Per-writer cryptographic signing is the future Crux-5 control; it is not
    // bound at write time today.
    per_writer_signature: null,
    signing_status: "not_bound",
    // The persistable taint is enforced by the write-gate at write time but is
    // not stored retrievably on the passage, so it cannot be reported here.
    taint_retrievable: false,
    // A passage insert does not automatically append a signer-bound provenance
    // event today (memory_attest is a separate, manual attestation).
    automatic_provenance_event: false,
    note:
      "Tamper-evidence today is the re-verified content hash. Per-writer signer " +
      "identity, a retrievable taint, and an automatic provenance event are the " +
      "future controls this tool is the seam for; they are not yet bound.",
  };
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

  return {
    name: "sdw_memory_provenance",
    description:
      "Show what is provable about a stored memory passage: whether it exists, " +
      "its content hash (re-verified on read, fails closed on mismatch), when it " +
      "was created, and how many encrypted chunks it spans. It also reports, " +
      "honestly, what is NOT yet bound: per-writer signer identity, a retrievable " +
      "taint, and an automatic provenance event. Use it to judge a passage before " +
      "trusting it; it does not claim to prove who wrote it.",
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
    handler: async (args) => {
      const passageId = args.passage_id;
      if (typeof passageId !== "string" || passageId.length === 0) {
        await auditFailure({ denial_class: "invalid_passage_id" });
        return deny();
      }
      try {
        const passage = await adapter.getPassage(passageId);
        if (passage === null) {
          await auditRead({ passage_id: passageId, found: false });
          return toolResult({ found: false });
        }
        await auditRead({ passage_id: passageId, found: true });
        // Public-safe provenance: the passage's own non-sensitive facts plus
        // the honest gaps block. No body text, no audit internals, no ids
        // beyond the caller's own passage/owner refs.
        return toolResult({
          found: true,
          provenance: {
            passage_id: passage.passage_id,
            owner_ref: passage.owner_ref,
            content_hash: passage.content_hash,
            content_hash_verified_on_read: true,
            created_at: passage.created_at,
            chunk_count: passage.chunk_count,
            tags: [...passage.tags],
          },
          provenance_gaps: provenanceGaps(),
        });
      } catch (error) {
        const category = error instanceof SdwValidationError ? error.category : "provenance_failed";
        await auditFailure({ denial_class: category });
        return deny();
      }
    },
  };
}
