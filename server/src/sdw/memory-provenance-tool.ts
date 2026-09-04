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
import {
  computeMemoryOriginProvenanceDigest,
  isMemoryTransferLineageRef,
  isMemoryTransportAdmissionChannel,
  type MemoryProvenanceCompanion,
} from "./memory-provenance-contract.js";

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
    const transport = isMemoryTransportAdmissionChannel(admission.admission_channel);
    // Foreign vs locally recorded origin is decided by the ORIGIN FORTRESS,
    // never by the channel: a transport channel also admits legacy V1 archive
    // rows whose origin this fortress signed itself at import. Must match the
    // same predicate in companionBindsPublicPassage below.
    const foreignOrigin = origin.origin_fortress_id !== admission.destination_fortress_id;
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
      // Transport admissions surface the import's lineage reference: an opaque
      // digest the import receipt already returned to the operator, naming the
      // transfer that admitted this passage. Never a key, a body, or a foreign
      // fortress identifier.
      ...(transport ? { transfer_lineage_ref: admission.transfer_lineage_ref } : {}),
      taint_retrievable: false,
      automatic_provenance_event: true,
      note: foreignOrigin
        ? "The origin binding was recorded by another fortress; this fortress's signed admission binds it to this exact passage and names the transfer lineage that admitted it. This does not prove true authorship, content truth, safety, or a remote identity."
        : transport
          ? "This fortress recorded the origin binding itself when it admitted this passage through a transfer; the admission names that transfer lineage and carries the admitted origin-trust tier. This does not prove true authorship, content truth, safety, or a remote identity."
          : "The fortress-recorded origin and admission bindings verify for this exact passage. This does not prove true authorship, content truth, safety, or a remote identity.",
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

/**
 * Binds the companion the backend returned to the passage a SEPARATE read
 * produced, so a companion that describes passage X can never be reported as
 * the provenance of passage Y (the two reads are not one transaction).
 *
 * Rule 7 (AGENTS.md): the subject of every field checked here is THIS local
 * passage; the evidence source is the companion the backend already
 * signature-verified (status `verified` is the precondition for reaching this
 * function); the verifier of those signatures is the backend's signer
 * resolver, not this wrapper; consuming a `true` here means only "the
 * verified companion describes the passage in hand", nothing about
 * authorship or truth.
 *
 * Two branches, both safe:
 *  - Local admissions (`local_write`, `legacy_migration`,
 *    `operator_readmission`): this fortress signed the origin about THIS
 *    passage, so the origin's own subject (`passage_id`, `owner_ref`) must
 *    name the local passage.
 *  - Transport admissions (`MEMORY_TRANSPORT_ADMISSION_CHANNELS`) whose origin
 *    fortress is NOT this fortress: the origin was signed by the SOURCE
 *    fortress and legitimately carries the source's passage id and owner
 *    ref; the destination re-derived a local id at import. (A transport
 *    admission whose origin fortress IS this fortress, the legacy V1 archive
 *    row, was origin-signed here at import about the local id, so it takes
 *    the local branch's direct subject check as well as the digest binding.)
 *    The mapping source-id -> local-id is the destination-signed
 *    admission written atomically with the passage at import: it names the
 *    local `passage_id` and `destination_owner_ref`, commits to the exact
 *    origin through `origin_provenance_digest`, and carries the import's
 *    `transfer_lineage_ref`. This branch therefore recomputes the origin
 *    digest and requires it to equal the digest the admission was signed
 *    over, and refuses when the lineage reference is absent. An origin
 *    swapped in from another imported passage fails the digest equality; a
 *    tampered admission never reaches here because the backend's signature
 *    check would have quarantined it. The check is never relaxed to "any id".
 *
 * Both branches share the destination binding (the admission names this
 * passage and owner) and the content binding (the origin's hash and chunk
 * count match the passage read back). The channel set MUST match
 * `MEMORY_TRANSPORT_ADMISSION_CHANNELS` in memory-provenance-contract.ts,
 * where `parseAdmissionBody` requires the lineage on exactly those channels.
 */
function companionBindsPublicPassage(
  companion: MemoryProvenanceCompanion,
  passage: MemoryPassage,
): boolean {
  const origin = companion.origin.body;
  const admission = companion.admission.body;
  const destinationBound =
    admission.passage_id === passage.passage_id &&
    admission.destination_owner_ref === passage.owner_ref &&
    origin.content_hash === passage.content_hash &&
    origin.chunk_count === passage.chunk_count;
  if (!destinationBound) return false;
  // The admission is evidence about ONE origin: the digest it was signed over
  // must be the digest of the origin presented alongside it. Recomputed here,
  // never read from the companion's own claim.
  const originDigest = computeMemoryOriginProvenanceDigest(companion.origin);
  if (originDigest !== companion.origin_provenance_digest ||
      originDigest !== admission.origin_provenance_digest) {
    return false;
  }
  // Same predicate as provenanceGaps: the origin fortress, not the channel,
  // decides whether the origin's own subject can be checked directly.
  const foreignOrigin = origin.origin_fortress_id !== admission.destination_fortress_id;
  if (isMemoryTransportAdmissionChannel(admission.admission_channel)) {
    // Imported: the local binding is the import-time mapping above; the
    // lineage reference is what makes that mapping an import record rather
    // than a bare re-labelling, so its absence fails closed. Validity is the
    // SAME predicate parseAdmissionBody applies (memory-provenance-contract.ts,
    // isMemoryTransferLineageRef): one definition of a lineage reference.
    if (!isMemoryTransferLineageRef(admission.transfer_lineage_ref)) return false;
    if (foreignOrigin) return true;
    // Locally origin-signed transport row (legacy V1 archive import): the
    // direct subject check holds and is therefore required, not skipped.
  } else if (foreignOrigin) {
    // A non-transport channel never carries another fortress's origin.
    return false;
  }
  // Locally recorded: the origin itself must name this passage.
  return origin.passage_id === passage.passage_id &&
    origin.owner_ref === passage.owner_ref;
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
    if ((await options.isolationGuard("sdw_memory_provenance")).allowed) return false;
    await auditFailure({ denial_class: SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS });
    return true;
  };

  return {
    name: "sdw_memory_provenance",
    description:
      "Show per-record SDW memory integrity status. Verified rows expose the " +
      "bounded fortress-recorded origin/admission classes; a passage admitted " +
      "through a memory archive import reports its origin-trust tier and " +
      "the transfer lineage reference; unsigned PRE_MIGRATION rows are explicit. " +
      "Verification does not prove true authorship, content truth, safety, or a " +
      "remote identity.",
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
