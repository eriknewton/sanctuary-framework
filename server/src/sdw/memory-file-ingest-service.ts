/**
 * Shared, in-process memory-file ingest sequence for trusted entry points.
 *
 * Authorization belongs to the caller: this function does not turn an agent
 * argument into consent. The caller supplies fixed fortress-bound adapter,
 * source directory, harness, owner, and an authorization callback that has
 * already bound its decision to those same values. No vault write happens
 * until that callback allows the request and the write-ahead audit is durable.
 */

import type { AuditLog } from "../operational/audit-log.js";
import {
  CLAUDE_CODE_MEMORY_HARNESS,
  commitClaudeCodeMemorySnapshot,
  readClaudeCodeMemoryDirectory,
  screenClaudeCodeMemorySnapshot,
} from "./adapters/claude-code-file-adapter.js";
import {
  CODEX_MEMORY_HARNESS,
  commitCodexMemorySnapshot,
  readCodexMemoryDirectory,
  screenCodexMemorySnapshot,
} from "./adapters/codex-memory-file-adapter.js";
import { MEMORY_INGEST_CLASSIFIER_OVERRIDE } from "./adapters/memory-file-allow-list.js";
import type { MemoryBackendAdapter, MemoryPassage } from "./adapters/memory-backend.js";

export type MemoryFileHarness =
  | typeof CLAUDE_CODE_MEMORY_HARNESS
  | typeof CODEX_MEMORY_HARNESS;

/** Existing CLI authorization outcomes. A future broker must add its own
 * independently reviewed authorization kind, never label a grant as Tier 3. */
export type MemoryIngestAuthorization =
  | { readonly approvalBasis: "operator_policy_tier3"; readonly policyTier: 3; readonly approvalAuditId?: string }
  | { readonly approvalBasis: "human"; readonly policyTier: 1 | 2; readonly approvalAuditId: string };

export interface MemoryIngestRequest {
  readonly adapter: MemoryBackendAdapter;
  readonly auditLog: AuditLog;
  readonly harness: MemoryFileHarness;
  readonly sourceDir: string;
  readonly ownerRef: string;
  readonly allowFiles: ReadonlySet<string>;
  /** Return null to deny. The callback is a trusted composition-root input. */
  readonly authorize: () => Promise<MemoryIngestAuthorization | null>;
  /**
   * Required final authorization check, after screening and durable prewrite
   * audit but immediately before the vault commit. A scoped-grant caller must
   * revalidate scope, expiry and revocation here; throwing aborts the write.
   */
  readonly beforeCommit: () => Promise<void>;
}

export interface MemoryIngestResult {
  readonly ingested: readonly MemoryPassage[];
  readonly skipped: readonly { readonly source_path: string; readonly reason: string; readonly detector?: string; readonly line?: number }[];
  readonly overridden: readonly { readonly source_path: string; readonly reason: string; readonly detector?: string; readonly line?: number }[];
  readonly unused_allow_files: readonly string[];
  readonly source_file_count: number;
  readonly complete: boolean;
}

/** A null result means the trusted authorization strategy denied the ingest. */
export async function ingestMemoryFiles(
  request: MemoryIngestRequest,
): Promise<MemoryIngestResult | null> {
  // An owner mismatch would turn an apparently scoped ingest into a write to
  // another owner's SDW namespace, so reject it before evaluating consent.
  if (request.adapter.ownerRef !== request.ownerRef) {
    throw new Error("memory ingest owner does not match the fortress adapter");
  }
  if (request.harness !== CLAUDE_CODE_MEMORY_HARNESS && request.harness !== CODEX_MEMORY_HARNESS) {
    throw new Error("unsupported memory ingest harness");
  }
  const authorization = await request.authorize();
  if (authorization === null) return null;
  // A classifier waiver requires a human approval receipt even when plain
  // ingest was relaxed by policy; never let a caller relabel it Tier 3.
  if (authorization.approvalBasis === "operator_policy_tier3" && request.allowFiles.size > 0) {
    throw new Error("classifier overrides require human approval");
  }
  if (authorization.approvalBasis === "human" && !authorization.approvalAuditId) {
    throw new Error("human memory ingest approval has no audit receipt");
  }

  let screened:
    | { readonly kind: "claude-code"; readonly value: ReturnType<typeof screenClaudeCodeMemorySnapshot> }
    | { readonly kind: "codex"; readonly value: ReturnType<typeof screenCodexMemorySnapshot> };
  if (request.harness === CLAUDE_CODE_MEMORY_HARNESS) {
    const snapshot = await readClaudeCodeMemoryDirectory(request.sourceDir);
    screened = {
      kind: "claude-code",
      value: screenClaudeCodeMemorySnapshot(request.adapter, snapshot, { allowFiles: request.allowFiles }),
    };
  } else {
    const snapshot = await readCodexMemoryDirectory(request.sourceDir);
    screened = {
      kind: "codex",
      value: screenCodexMemorySnapshot(request.adapter, snapshot, { allowFiles: request.allowFiles }),
    };
  }
  const outcome = screened.value.outcome;

  // Intent and per-file waiver evidence must be durable before any vault
  // write. A failed audit append aborts the entire commit phase.
  await request.auditLog.appendCritical({
    layer: "l1",
    operation: "memory_ingest_started",
    identity_id: "principal",
    result: "success",
    details: {
      harness: request.harness,
      source_dir: request.sourceDir,
      owner_ref: request.ownerRef,
      source_file_count: screened.value.source_file_count,
      allow_files: [...request.allowFiles].sort(),
      policy_tier: authorization.policyTier,
      approval_basis: authorization.approvalBasis,
      approval_audit_id: authorization.approvalAuditId,
    },
  });
  for (const override of outcome.overridden) {
    await request.auditLog.appendCritical({
      layer: "l1",
      operation: MEMORY_INGEST_CLASSIFIER_OVERRIDE,
      identity_id: "principal",
      result: "success",
      details: {
        harness: request.harness,
        source_dir: request.sourceDir,
        owner_ref: request.ownerRef,
        source_path: override.source_path,
        reason: override.reason,
        detector: override.detector,
        line: override.line,
      },
    });
  }

  // The source screen and audit appends take time. A future grant can be
  // revoked in that interval, so the final check is a required callback and
  // has no permissive default. The one-shot CLI approval supplies a no-op.
  await request.beforeCommit();

  const result = screened.kind === "claude-code"
    ? await commitClaudeCodeMemorySnapshot(request.adapter, screened.value)
    : await commitCodexMemorySnapshot(request.adapter, screened.value);
  await request.auditLog.appendCritical({
    layer: "l1",
    operation: "memory_ingest",
    identity_id: "principal",
    result: "success",
    details: {
      harness: request.harness,
      source_dir: request.sourceDir,
      owner_ref: request.ownerRef,
      source_file_count: result.source_file_count,
      committed_file_count: result.ingested.length,
      skipped_file_count: result.skipped.length,
      overridden_file_count: result.overridden.length,
      unused_allow_files: result.unused_allow_files,
      complete: result.complete,
      policy_tier: authorization.policyTier,
      approval_basis: authorization.approvalBasis,
      skipped: result.skipped.map((skip) => ({ source_path: skip.source_path, reason: skip.reason })),
      approval_audit_id: authorization.approvalAuditId,
    },
  });
  return result;
}
