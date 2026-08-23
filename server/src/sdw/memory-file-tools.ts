/**
 * MCP tools for manual memory-file transcode into and out of the SDW vault.
 *
 * Rung-1 is portability, not sync: these handlers run only when invoked. They
 * never watch harness directories and never write back into a harness source
 * tree. Claude Code/Codex live-file replacement waits for a later, drilled
 * adapter-mediated read path.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import { fixedDenial } from "../agent-native/safety-base.js";
import type { MemoryBackendAdapter } from "./adapters/memory-backend.js";
import {
  CLAUDE_CODE_MEMORY_HARNESS,
  commitClaudeCodeMemorySnapshot,
  emitClaudeCodeMemoryDirectory,
  readClaudeCodeMemoryDirectory,
  screenClaudeCodeMemorySnapshot,
} from "./adapters/claude-code-file-adapter.js";
import {
  CODEX_MEMORY_HARNESS,
  commitCodexMemorySnapshot,
  emitCodexMemoryDirectory,
  readCodexMemoryDirectory,
  screenCodexMemorySnapshot,
} from "./adapters/codex-memory-file-adapter.js";
import { SdwValidationError, sdwClassifierReasonText } from "./errors.js";
import { MEMORY_INGEST_CLASSIFIER_OVERRIDE } from "./adapters/memory-file-allow-list.js";
import {
  createMultiAgentIsolationGuard,
  type MultiAgentIsolationGuard,
} from "./memory-isolation.js";
import {
  MEMORY_TRANSCODE_MODE,
  restoreMemoryTranscodeArchive,
  transcodeMemoryDirectory,
} from "./memory-transcode.js";

export interface SdwMemoryFileToolsOptions {
  /** The shipped sovereign passage backend, already scoped to one owner_ref. */
  readonly adapter: MemoryBackendAdapter;
  readonly auditLog: AuditLog;
  /**
   * Resolver for the CALLING wrapped-agent identity. Same shared-owner-scope
   * problem the memory read/write tools have, with a sharper edge: memory_emit
   * materializes the WHOLE shared corpus as plaintext files, so a second
   * wrapped agent refused by memory_get must not be able to reach the same
   * bytes through emit.
   *
   * Ignored when `isolationGuard` is supplied. Prefer the shared guard: two
   * guards over one scope each pin their own first caller.
   */
  readonly ownerIdentity?: () => string | undefined;
  /** Guard shared with the other tool families over the same owner scope. */
  readonly isolationGuard?: MultiAgentIsolationGuard;
  readonly now?: () => string;
}

type SupportedMemoryHarness =
  | typeof CLAUDE_CODE_MEMORY_HARNESS
  | typeof CODEX_MEMORY_HARNESS;

const SUPPORTED_HARNESSES: readonly SupportedMemoryHarness[] = [
  CLAUDE_CODE_MEMORY_HARNESS,
  CODEX_MEMORY_HARNESS,
];

/**
 * Sole source for the Rung-1 memory-file claim surfaces.
 *
 * The structure guard imports these exact production strings. Keep the bounds
 * explicit: only the vault copy is encrypted, harness files are plaintext,
 * and a configured model vendor can read memory supplied at inference.
 */
export const RUNG1_MEMORY_TOOL_DESCRIPTIONS = {
  memory_ingest:
    "Manually mirror a Claude Code or Codex memory directory into the SDW vault. It " +
    "reads plaintext source files and leaves them untouched; the encrypted " +
    "copy lives in the vault. Files the secret classifier refuses are " +
    "skipped and named in the result, so check skipped_file_count before " +
    "treating the mirror as complete. Optional allow_files names exact source " +
    "paths to ingest as-is even though the classifier refuses them; each use " +
    "is audited by path and reported under overridden, and a listed path the " +
    "classifier never refused is reported as unused, not silently accepted. " +
    "A call naming allow_files always requires operator approval, even if a " +
    "custom policy relaxed memory_ingest itself. This does not sync, watch, or replace " +
    "the harness write path, and memory later sent to a model vendor is " +
    "exposed to that vendor at inference.",
  memory_emit:
    "Manually emit Claude Code or Codex memory files from the SDW vault into an " +
    "operator-named output directory. Existing memory files are never " +
    "overwritten. The result reports index_present; false means the emitted " +
    "tree cannot be re-ingested as that harness's memory directory. Emitted " +
    "files are plaintext for the harness; " +
    "this does not sync or write back to the source memory directory, and " +
    "memory later sent to a model vendor is exposed to that vendor at inference.",
  memory_transcode:
    "Manually project one already-mirrored Claude Code or Codex memory snapshot " +
    "from the encrypted SDW vault into the other harness format. The output is " +
    "plaintext and may be structurally lossy; exact source recovery uses the " +
    "versioned encrypted archive returned as archive_id, not the projection. " +
    "Existing output files are never overwritten. This does not sync, watch, or " +
    "replace either harness write path, and memory later sent to a model vendor " +
    "is exposed to that vendor at inference.",
  memory_transcode_restore:
    "Manually restore the exact source files from a completed encrypted Sanctuary " +
    "memory transcode archive into an empty operator-named directory. Restored " +
    "files are plaintext and existing files are never overwritten. This does not " +
    "sync, watch, or write back to a live harness directory, and memory later sent " +
    "to a model vendor is exposed to that vendor at inference.",
} as const;

export interface MemoryFileApprovalContext {
  /** The SDW owner scope whose memory this call reads or writes. */
  readonly ownerRef: string;
  /** Calling wrapped-agent identity, when one is resolvable. */
  readonly agentId?: string | undefined;
}

/**
 * Tier-1 approval projection. Memory file BODIES never enter the approval
 * channel (Hard Constraint #1), but the operator does have to be told WHOSE
 * memory a dump moves: {harness, dir} alone cannot distinguish "export my own
 * notes" from "materialize the shared corpus for some other agent".
 */
export function memoryFileApprovalArgs(
  args: Record<string, unknown>,
  context?: MemoryFileApprovalContext,
): Record<string, unknown> {
  const projected: Record<string, unknown> = {};
  if (typeof args.harness === "string") projected.harness = args.harness;
  if (typeof args.from_harness === "string") projected.from_harness = args.from_harness;
  if (typeof args.to_harness === "string") projected.to_harness = args.to_harness;
  if (typeof args.mode === "string") projected.mode = args.mode;
  if (typeof args.archive_id === "string") projected.archive_id = args.archive_id;
  if (typeof args.dir === "string") projected.dir = args.dir;
  // Rung-1 point 3: memory_ingest's allow_files waives the secret classifier
  // for exactly these paths, so the operator approving the call must see
  // which paths are waived, the same reasoning as the owner_ref/agent_id
  // projection below for WHOSE memory moves.
  if (Array.isArray(args.allow_files)) {
    const allowFiles = args.allow_files.filter(
      (item): item is string => typeof item === "string",
    );
    if (allowFiles.length > 0) projected.allow_files = allowFiles;
  }
  if (context !== undefined) {
    projected.owner_ref = context.ownerRef;
    projected.agent_id = context.agentId ?? null;
  }
  return projected;
}

function asSupportedHarness(value: unknown): SupportedMemoryHarness | null {
  return typeof value === "string" &&
    (SUPPORTED_HARNESSES as readonly string[]).includes(value)
    ? (value as SupportedMemoryHarness)
    : null;
}

function asDirectory(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

/** No paths allow-listed: the default when the caller omits allow_files. */
const EMPTY_ALLOW_FILES: ReadonlySet<string> = new Set();

/**
 * `allow_files` is optional; when supplied it must be an array of non-empty
 * strings (the exact source paths to waive the classifier for). Anything else
 * is invalid_args, same as a malformed harness or dir.
 */
function asAllowFiles(value: unknown): ReadonlySet<string> | null {
  if (value === undefined) return EMPTY_ALLOW_FILES;
  if (!Array.isArray(value)) return null;
  const allowFiles = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string" || item.trim().length === 0) return null;
    allowFiles.add(item);
  }
  return allowFiles;
}

function asArchiveId(value: unknown): string | null {
  return typeof value === "string" && /^[a-f0-9]{32}$/.test(value) ? value : null;
}

function denialCategory(error: unknown, fallback: string): string {
  return error instanceof SdwValidationError ? error.category : fallback;
}

function errorCauseDetail(error: unknown): Record<string, string> {
  const cause = errorCauseMessage(errorCause(error));
  if (error instanceof SdwValidationError) {
    return cause === undefined ? {} : { error_cause: cause };
  }
  return { error_message: errorMessage(error) };
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "Error";
}

function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const cause = errorCauseMessage(errorCause(error));
  return cause === undefined ? message : `${message}; cause: ${cause}`;
}

function errorCause(error: unknown): unknown {
  return error instanceof Error ? error.cause : undefined;
}

function errorCauseMessage(cause: unknown): string | undefined {
  if (cause === undefined) return undefined;
  if (cause instanceof AggregateError) {
    return cause.errors.map((item) => errorCauseMessage(item) ?? String(item)).join("; ");
  }
  if (cause instanceof Error) return cause.message;
  return String(cause);
}

export function createSdwMemoryFileTools(options: SdwMemoryFileToolsOptions): ToolDefinition[] {
  const { adapter, auditLog } = options;
  const now = options.now ?? (() => new Date().toISOString());
  const isolationGuard =
    options.isolationGuard ?? createMultiAgentIsolationGuard(options.ownerIdentity);
  const approvalArgs = (args: Record<string, unknown>): Record<string, unknown> =>
    memoryFileApprovalArgs(args, {
      ownerRef: adapter.ownerRef,
      agentId: options.ownerIdentity?.(),
    });

  const auditFailure = (operation: string, details: Record<string, unknown>): Promise<void> =>
    auditLog.appendCritical({
      layer: "l1",
      operation,
      identity_id: "system",
      result: "failure",
      details,
    });

  const auditSuccess = (operation: string, details: Record<string, unknown>): Promise<void> =>
    auditLog.appendCritical({
      layer: "l1",
      operation,
      identity_id: "principal",
      result: "success",
      details,
    });

  const deny = (operation: string) =>
    toolResult(fixedDenial(`audit:${operation}`, "request_review", null));

  const refuseSecondIdentity = async (operation: string): Promise<boolean> => {
    if (isolationGuard(operation).allowed) return false;
    await auditFailure(`${operation}_denied`, { denial_class: "owner_scope_conflict" });
    return true;
  };

  const memoryIngest: ToolDefinition = {
    name: "memory_ingest",
    description: RUNG1_MEMORY_TOOL_DESCRIPTIONS.memory_ingest,
    tool_class: "write",
    approvalTargetArgs: approvalArgs,
    inputSchema: {
      type: "object",
      properties: {
        harness: {
          type: "string",
          enum: [...SUPPORTED_HARNESSES],
          description: "Harness memory-file format to ingest",
        },
        dir: {
          type: "string",
          description: "Path to the harness memory directory to read",
        },
        allow_files: {
          type: "array",
          items: { type: "string" },
          description:
            "Exact source paths to ingest as-is even if the secret classifier " +
            "refuses them: each must be the source filename exactly as the " +
            "ingest result's skipped/overridden entries name it (e.g. Codex " +
            "raw_memories.md, not memories/raw_memories.md), never a glob or " +
            "a directory. Each use is audited by path; a listed path the " +
            "classifier never refused is reported as unused.",
        },
      },
      required: ["harness", "dir"],
    },
    handler: async (args) => {
      const harness = asSupportedHarness(args.harness);
      const dir = asDirectory(args.dir);
      const allowFiles = asAllowFiles(args.allow_files);
      if (harness === null || dir === null || allowFiles === null) {
        await auditFailure("memory_ingest_denied", { denial_class: "invalid_args" });
        return deny("memory_ingest");
      }
      if (await refuseSecondIdentity("memory_ingest")) return deny("memory_ingest");

      let fileCount = 0;
      const ingestedAt = now();
      try {
        // Preflight-only (HIGH-C2 fix round): screen decides accept / skip /
        // override and validates allow_files (assertAllowFilesKnown, inside
        // screenMemoryFileEntries) WITHOUT writing anything to the vault. The
        // override audit records below are durably appended, and can abort
        // the whole ingest, BEFORE commitClaudeCodeMemorySnapshot /
        // commitCodexMemorySnapshot ever runs, so a crash after this point
        // can only crash AFTER the waiver is already on the record, never
        // before.
        let screened:
          | { readonly kind: "claude-code"; readonly value: Awaited<ReturnType<typeof screenClaudeCodeMemorySnapshot>> }
          | { readonly kind: "codex"; readonly value: Awaited<ReturnType<typeof screenCodexMemorySnapshot>> };
        if (harness === CLAUDE_CODE_MEMORY_HARNESS) {
          const snapshot = await readClaudeCodeMemoryDirectory(dir, { ingestedAt });
          fileCount = snapshot.entries.length;
          screened = {
            kind: "claude-code",
            value: screenClaudeCodeMemorySnapshot(adapter, snapshot, { allowFiles }),
          };
        } else {
          const snapshot = await readCodexMemoryDirectory(dir, { ingestedAt });
          fileCount = snapshot.entries.length;
          screened = {
            kind: "codex",
            value: screenCodexMemorySnapshot(adapter, snapshot, { allowFiles }),
          };
        }
        const outcome = screened.value.outcome;

        // Write-ahead INTENT, not an outcome. The durable record precedes the
        // vault mutation so a crash mid-ingest still leaves evidence that an
        // ingest was attempted; it is labelled `_started` because at this
        // point nothing has been committed. allow_files is included here (not
        // only on the post-commit record and the per-file override record
        // below) because it is a PRE-WRITE WITNESS too, cheap insurance on
        // top of the HIGH-C2 ordering below.
        await auditSuccess("memory_ingest_started", {
          harness,
          source_dir: dir,
          owner_ref: adapter.ownerRef,
          source_file_count: fileCount,
          allow_files: [...allowFiles].sort(),
        });

        // One record per overridden file (Rung-1 point 3), durably appended
        // BEFORE any vault write (HIGH-C2 fix round): the operator waived the
        // classifier for this exact path, so it is named individually rather
        // than folded into the aggregate outcome record below. Carries the
        // refusal metadata the classifier would have reported (detector,
        // line), never the matched content. If ANY of these audit writes
        // throws, the catch block below denies the whole ingest and NOTHING
        // is committed -- the ordering test in test/sdw/memory-file-tools.test.ts
        // proves this by injecting a failure at the first putPassages call and
        // asserting the override record is present anyway.
        for (const override of outcome.overridden) {
          await auditSuccess(MEMORY_INGEST_CLASSIFIER_OVERRIDE, {
            harness,
            source_dir: dir,
            owner_ref: adapter.ownerRef,
            source_path: override.source_path,
            reason: override.reason,
            detector: override.detector,
            line: override.line,
          });
        }

        const result =
          screened.kind === "claude-code"
            ? await commitClaudeCodeMemorySnapshot(adapter, screened.value)
            : await commitCodexMemorySnapshot(adapter, screened.value);
        await auditSuccess("memory_ingest", {
          harness,
          source_dir: dir,
          owner_ref: adapter.ownerRef,
          source_file_count: result.source_file_count,
          committed_file_count: result.ingested.length,
          skipped_file_count: result.skipped.length,
          overridden_file_count: result.overridden.length,
          unused_allow_files: result.unused_allow_files,
          complete: result.complete,
          skipped: result.skipped.map((skip) => ({
            source_path: skip.source_path,
            reason: skip.reason,
          })),
        });
        return toolResult({
          ingested: true,
          harness,
          complete: result.complete,
          source_file_count: result.source_file_count,
          file_count: result.ingested.length,
          skipped_file_count: result.skipped.length,
          skipped: result.skipped.map((skip) => ({
            source_path: skip.source_path,
            reason: skip.reason,
            detail: skip.detail,
            detector: skip.detector,
            line: skip.line,
            // The same plain-English text the
            // CLI prints, resolved from the shared table so an MCP caller does
            // not have to re-derive it from `detector`. Class and location
            // only, never the matched content.
            reason_text: sdwClassifierReasonText(skip.reason, skip.detector),
          })),
          overridden_file_count: result.overridden.length,
          overridden: result.overridden.map((override) => ({
            source_path: override.source_path,
            reason: override.reason,
            detail: override.detail,
            detector: override.detector,
            line: override.line,
            reason_text: sdwClassifierReasonText(override.reason, override.detector),
          })),
          unused_allow_files: result.unused_allow_files,
          passages: result.ingested.map((passage) => ({
            passage_id: passage.passage_id,
            content_hash: passage.content_hash,
            source_path:
              passage.metadata.find((entry) => entry.key === "source_path")?.value ?? null,
          })),
        });
      } catch (error) {
        await auditFailure("memory_ingest_denied", {
          denial_class: denialCategory(error, "ingest_failed"),
          error_class: errorName(error),
          ...errorCauseDetail(error),
          harness,
          owner_ref: adapter.ownerRef,
          source_file_count: fileCount,
          committed_file_count: 0,
        });
        return deny("memory_ingest");
      }
    },
  };

  const memoryEmit: ToolDefinition = {
    name: "memory_emit",
    description: RUNG1_MEMORY_TOOL_DESCRIPTIONS.memory_emit,
    tool_class: "write",
    approvalTargetArgs: approvalArgs,
    inputSchema: {
      type: "object",
      properties: {
        harness: {
          type: "string",
          enum: [...SUPPORTED_HARNESSES],
          description: "Harness memory-file format to emit",
        },
        dir: {
          type: "string",
          description: "Output directory; existing memory files are never overwritten",
        },
      },
      required: ["harness", "dir"],
    },
    handler: async (args) => {
      const harness = asSupportedHarness(args.harness);
      const dir = asDirectory(args.dir);
      if (harness === null || dir === null) {
        await auditFailure("memory_emit_denied", { denial_class: "invalid_args" });
        return deny("memory_emit");
      }
      if (await refuseSecondIdentity("memory_emit")) return deny("memory_emit");

      try {
        // Write-ahead INTENT: durable before any plaintext file is materialized
        // from the vault, and labelled `_started` because no file exists yet.
        await auditSuccess("memory_emit_started", {
          harness,
          output_dir: dir,
          owner_ref: adapter.ownerRef,
        });
        const result = harness === CLAUDE_CODE_MEMORY_HARNESS
          ? await emitClaudeCodeMemoryDirectory(adapter, dir)
          : await emitCodexMemoryDirectory(adapter, dir);
        await auditSuccess("memory_emit", {
          harness,
          output_dir: dir,
          owner_ref: adapter.ownerRef,
          emitted_file_count: result.emitted.length,
          index_present: result.index_present,
        });
        return toolResult({
          emitted: true,
          harness,
          file_count: result.emitted.length,
          index_present: result.index_present,
          files: result.emitted,
        });
      } catch (error) {
        await auditFailure("memory_emit_denied", {
          denial_class: denialCategory(error, "emit_failed"),
          error_class: errorName(error),
          ...errorCauseDetail(error),
          harness,
          owner_ref: adapter.ownerRef,
          emitted_file_count: 0,
        });
        return deny("memory_emit");
      }
    },
  };

  const memoryTranscode: ToolDefinition = {
    name: "memory_transcode",
    description: RUNG1_MEMORY_TOOL_DESCRIPTIONS.memory_transcode,
    tool_class: "write",
    approvalTargetArgs: approvalArgs,
    inputSchema: {
      type: "object",
      properties: {
        from_harness: {
          type: "string",
          enum: [...SUPPORTED_HARNESSES],
          description: "Harness format already mirrored into this owner-scoped vault",
        },
        to_harness: {
          type: "string",
          enum: [...SUPPORTED_HARNESSES],
          description: "Different harness format to project as plaintext",
        },
        dir: {
          type: "string",
          description: "Empty output directory; existing files are never overwritten",
        },
        mode: {
          type: "string",
          enum: [MEMORY_TRANSCODE_MODE],
          description: "Frozen reversible archive plus native plaintext projection",
        },
      },
      required: ["from_harness", "to_harness", "dir", "mode"],
    },
    handler: async (args) => {
      const fromHarness = asSupportedHarness(args.from_harness);
      const toHarness = asSupportedHarness(args.to_harness);
      const dir = asDirectory(args.dir);
      if (
        fromHarness === null ||
        toHarness === null ||
        fromHarness === toHarness ||
        dir === null ||
        args.mode !== MEMORY_TRANSCODE_MODE
      ) {
        await auditFailure("memory_transcode_denied", { denial_class: "invalid_args" });
        return deny("memory_transcode");
      }
      if (await refuseSecondIdentity("memory_transcode")) return deny("memory_transcode");

      try {
        await auditSuccess("memory_transcode_started", {
          from_harness: fromHarness,
          to_harness: toHarness,
          mode: MEMORY_TRANSCODE_MODE,
          output_dir: dir,
          owner_ref: adapter.ownerRef,
        });
        const result = await transcodeMemoryDirectory(adapter, fromHarness, toHarness, dir, {
          now,
        });
        try {
          await auditSuccess("memory_transcode", {
            archive_id: result.archive_id,
            from_harness: result.from_harness,
            to_harness: result.to_harness,
            mode: result.mode,
            output_dir: dir,
            owner_ref: adapter.ownerRef,
            source_file_count: result.source_file_count,
            projection_file_count: result.projection_file_count,
            source_set_sha256: result.source_set_sha256,
            projection_set_sha256: result.projection_set_sha256,
          });
        } catch (auditError) {
          return toolResult({
            transcoded: true,
            ...result,
            audit_outcome_recorded: false,
            operator_review_required: true,
            audit_error_class: errorName(auditError),
          });
        }
        return toolResult({ transcoded: true, ...result, audit_outcome_recorded: true });
      } catch (error) {
        await auditFailure("memory_transcode_denied", {
          denial_class: denialCategory(error, "transcode_failed"),
          error_class: errorName(error),
          ...errorCauseDetail(error),
          from_harness: fromHarness,
          to_harness: toHarness,
          mode: MEMORY_TRANSCODE_MODE,
          output_dir: dir,
          owner_ref: adapter.ownerRef,
        });
        return deny("memory_transcode");
      }
    },
  };

  const memoryTranscodeRestore: ToolDefinition = {
    name: "memory_transcode_restore",
    description: RUNG1_MEMORY_TOOL_DESCRIPTIONS.memory_transcode_restore,
    tool_class: "write",
    approvalTargetArgs: approvalArgs,
    inputSchema: {
      type: "object",
      properties: {
        archive_id: {
          type: "string",
          pattern: "^[a-f0-9]{32}$",
          description: "Opaque archive_id returned by memory_transcode",
        },
        dir: {
          type: "string",
          description: "Empty output directory; existing files are never overwritten",
        },
      },
      required: ["archive_id", "dir"],
    },
    handler: async (args) => {
      const archiveId = asArchiveId(args.archive_id);
      const dir = asDirectory(args.dir);
      if (archiveId === null || dir === null) {
        await auditFailure("memory_transcode_restore_denied", {
          denial_class: "invalid_args",
        });
        return deny("memory_transcode_restore");
      }
      if (await refuseSecondIdentity("memory_transcode_restore")) {
        return deny("memory_transcode_restore");
      }

      try {
        await auditSuccess("memory_transcode_restore_started", {
          archive_id: archiveId,
          output_dir: dir,
          owner_ref: adapter.ownerRef,
        });
        const result = await restoreMemoryTranscodeArchive(adapter, archiveId, dir);
        try {
          await auditSuccess("memory_transcode_restore", {
            archive_id: archiveId,
            source_harness: result.source_harness,
            output_dir: dir,
            owner_ref: adapter.ownerRef,
            restored_file_count: result.source_file_count,
            source_set_sha256: result.source_set_sha256,
          });
        } catch (auditError) {
          return toolResult({
            ...result,
            audit_outcome_recorded: false,
            operator_review_required: true,
            audit_error_class: errorName(auditError),
          });
        }
        return toolResult({ ...result, audit_outcome_recorded: true });
      } catch (error) {
        await auditFailure("memory_transcode_restore_denied", {
          denial_class: denialCategory(error, "restore_failed"),
          error_class: errorName(error),
          ...errorCauseDetail(error),
          archive_id: archiveId,
          output_dir: dir,
          owner_ref: adapter.ownerRef,
        });
        return deny("memory_transcode_restore");
      }
    },
  };

  return [memoryIngest, memoryEmit, memoryTranscode, memoryTranscodeRestore];
}
