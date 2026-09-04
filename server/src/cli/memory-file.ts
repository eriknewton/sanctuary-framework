/**
 * Manual memory-file ingest, emit, transcode, and archive-restore CLI wrappers.
 *
 * These are manual transcode commands. They use the same SDW memory backend as
 * the MCP tools and deliberately do not watch, sync, or modify harness-owned
 * source files.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { Writable } from "node:stream";

import { loadConfig } from "../config.js";
import { unlockLocalFortress } from "./local-fortress-unlock.js";
import {
  createLocalHumanApprovalInteraction,
  type MemoryArchiveDialogRunner,
} from "./memory-archive.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { AuditLog } from "../operational/audit-log.js";
import { BaselineTracker } from "../principal-policy/baseline.js";
import { ApprovalGate } from "../principal-policy/gate.js";
import { loadPrincipalPolicy } from "../principal-policy/loader.js";
import {
  CLAUDE_CODE_MEMORY_HARNESS,
  commitClaudeCodeMemorySnapshot,
  emitClaudeCodeMemoryDirectory,
  readClaudeCodeMemoryDirectory,
  screenClaudeCodeMemorySnapshot,
} from "../sdw/adapters/claude-code-file-adapter.js";
import {
  CODEX_MEMORY_HARNESS,
  commitCodexMemorySnapshot,
  emitCodexMemoryDirectory,
  readCodexMemoryDirectory,
  screenCodexMemorySnapshot,
} from "../sdw/adapters/codex-memory-file-adapter.js";
import { SdwValidationError, sdwClassifierReasonText } from "../sdw/errors.js";
import { SdwMemoryBackendAdapter } from "../sdw/adapters/sdw-memory-backend.js";
import { MEMORY_INGEST_CLASSIFIER_OVERRIDE } from "../sdw/adapters/memory-file-allow-list.js";
import {
  MEMORY_TRANSCODE_MODE,
  restoreMemoryTranscodeArchive,
  transcodeMemoryDirectory,
} from "../sdw/memory-transcode.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import type { MasterWriteBarrierLease } from "../storage/cross-process-lock.js";
import { IdentityManager } from "../cognitive/tools.js";
import { createPrimaryMemoryProvenancePublicKeyResolver, createPrimaryMemoryProvenanceSigningHandleResolver } from "../sdw/memory-provenance-signing.js";
import { SdwMemoryProvenanceMigration } from "../sdw/memory-provenance-migration.js";
import {
  consumeFlagValue,
  consumeFlagValues,
  flagValue,
  fortressFlagRefusalText,
  hasFlag,
} from "./argv.js";

export interface MemoryFileCommandArgs {
  readonly argv: string[];
  readonly out?: Writable;
  readonly err?: Writable;
  readonly env?: NodeJS.ProcessEnv;
  /** Stdin source for `--passphrase-stdin` (tests inject a Readable). */
  readonly stdin?: NodeJS.ReadableStream;
  /**
   * Test seam: receives a REFERENCE to the unlocked master buffer at bootstrap,
   * so a test can assert the verb's `finally` zeroed it on every path — including
   * when the body errors and when the audit flush throws — without printing the
   * bytes. Production leaves it undefined.
   */
  readonly observeMasterKey?: (buf: Uint8Array) => void;
  readonly dialogRunner?: MemoryArchiveDialogRunner;
}

const DEFAULT_OWNER_REF = "fleet-self";
/**
 * Bound on the `--passphrase-stdin` read so a pipe that is opened and never
 * written does not hang the command forever. An empty read falls through to the
 * normal "no credential supplied" refusal.
 */
const STDIN_READ_DEADLINE_MS = 30_000;
export const PASSPHRASE_ARGV_WARNING =
  "Warning: --passphrase puts the fortress passphrase in this process's argv, " +
  "where any local user can read it from the process list. Use " +
  "SANCTUARY_PASSPHRASE or --passphrase-stdin instead.\n";

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runMemoryIngestCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printIngestHelp(out);
    return 0;
  }

  const parsed = parseCommonArgs(args.argv, "memory_ingest", err);
  if (!parsed) return 2;
  // Rung-1 point 3: an explicit, named, per-file escape hatch, never a global
  // force flag. Each path is exact-match only (no globs, no directories) and
  // is checked against the actual source directory listing below; an unknown
  // path is an error (see assertAllowFilesKnown in memory-file-allow-list.ts),
  // not a silently ignored one. consumeFlagValues (not the bare flagValues
  // scan) so a trailing bare --allow-file, or --allow-file followed by
  // another flag, is a loud parse error instead of a silently dropped or
  // silently wrong waiver: a requested waiver must never vanish quietly.
  const allowFileFlags = consumeFlagValues(args.argv, "--allow-file");
  if (allowFileFlags.error !== undefined) {
    write(err, `memory_ingest: ${allowFileFlags.error}
`);
    return 2;
  }
  const allowFiles: ReadonlySet<string> = new Set(allowFileFlags.values);

  // S4: memory_ingest is a Tier-1 operation in principal-policy (loader.ts), so
  // it MUST pass the human ApprovalGate like emit/transcode/restore do. Without
  // this a same-uid process could write operator-signed provenance records into
  // the vault with no prompt — a claim/gate mismatch. The channel is built
  // before unlock so a missing local approval interaction fails closed early.
  const approvalChannel = createLocalHumanApprovalInteraction(args.dialogRunner, err);
  if (!approvalChannel) return 1;

  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin, args.observeMasterKey);
  if (!boot) return 1;

  try {
    // Tier-1 gate FIRST: no vault write, audit intent, or classifier override is
    // recorded until the local operator approves this exact ingest.
    const decision = await new ApprovalGate(
      await loadPrincipalPolicy(boot.fortressPath),
      boot.baseline,
      approvalChannel,
      boot.auditLog,
    ).evaluate("memory_ingest", {
      agent_id: null,
      harness: parsed.harness,
      source_dir: parsed.dir,
      owner_ref: parsed.ownerRef,
    });
    if (!decision.allowed || !decision.approval_audit_id) {
      write(err, "Denied: memory ingest was not approved by the local operator.\n");
      return 1;
    }
    let sourceFileCount = 0;
    // Preflight-only: screen decides accept / skip /
    // override and validates allow_files (assertAllowFilesKnown, inside
    // screenMemoryFileEntries) WITHOUT writing anything to the vault. The
    // override audit records below are durably appended, and can abort the
    // whole ingest, BEFORE the commit call further down ever runs, so a
    // crash after this point can only crash AFTER the waiver is already on
    // the record, never before.
    let screened:
      | { readonly kind: "claude-code"; readonly value: ReturnType<typeof screenClaudeCodeMemorySnapshot> }
      | { readonly kind: "codex"; readonly value: ReturnType<typeof screenCodexMemorySnapshot> };
    if (parsed.harness === CLAUDE_CODE_MEMORY_HARNESS) {
      const snapshot = await readClaudeCodeMemoryDirectory(parsed.dir);
      sourceFileCount = snapshot.entries.length;
      screened = {
        kind: "claude-code",
        value: screenClaudeCodeMemorySnapshot(boot.adapter, snapshot, { allowFiles }),
      };
    } else {
      const snapshot = await readCodexMemoryDirectory(parsed.dir);
      sourceFileCount = snapshot.entries.length;
      screened = {
        kind: "codex",
        value: screenCodexMemorySnapshot(boot.adapter, snapshot, { allowFiles }),
      };
    }
    const outcome = screened.value.outcome;

    // Write-ahead INTENT, durable before any vault write. If appendCritical
    // throws, the command aborts with no ingested memory files. It is labelled
    // `_started` because nothing is committed yet and the count is only what
    // was read. allow_files is included here (not only on the post-commit
    // record and the per-file override record below) because it is a
    // PRE-WRITE WITNESS too, cheap insurance on top of the screen-then-audit-
    // then-commit ordering below.
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_ingest_started",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        source_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        source_file_count: sourceFileCount,
        allow_files: [...allowFiles].sort(),
        approval_audit_id: decision.approval_audit_id,
      },
    });

    // One record per overridden file (Rung-1 point 3), durably appended
    // BEFORE any vault write: the operator waived the
    // classifier for this exact path, so the audit trail names it
    // individually rather than folding it into the aggregate outcome record
    // below. The refusal metadata the classifier would have reported is
    // retained here, never the matched content. If ANY of these audit writes
    // throws, the catch block below denies the whole ingest and NOTHING is
    // committed.
    for (const override of outcome.overridden) {
      await boot.auditLog.appendCritical({
        layer: "l1",
        operation: MEMORY_INGEST_CLASSIFIER_OVERRIDE,
        identity_id: "principal",
        result: "success",
        details: {
          harness: parsed.harness,
          source_dir: parsed.dir,
          owner_ref: parsed.ownerRef,
          source_path: override.source_path,
          reason: override.reason,
          detector: override.detector,
          line: override.line,
        },
      });
    }

    const result =
      screened.kind === "claude-code"
        ? await commitClaudeCodeMemorySnapshot(boot.adapter, screened.value)
        : await commitCodexMemorySnapshot(boot.adapter, screened.value);
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_ingest",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        source_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
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
        approval_audit_id: decision.approval_audit_id,
      },
    });
    write(
      out,
      `memory_ingest: ingested ${String(result.ingested.length)} of ${String(result.source_file_count)} ${harnessLabel(parsed.harness)} memory files into owner_ref ${parsed.ownerRef}\n`,
    );
    if (result.overridden.length > 0) {
      write(
        out,
        `memory_ingest: ${String(result.overridden.length)} file(s) were overridden (classifier refusal waived by --allow-file):\n`,
      );
      for (const override of result.overridden) {
        write(out, `  overridden ${override.source_path}: ${describeMemorySkipReason(override)}\n`);
      }
    }
    if (result.unused_allow_files.length > 0) {
      write(
        err,
        `memory_ingest: WARNING - --allow-file named ${String(result.unused_allow_files.length)} path(s) the classifier never refused (nothing was waived): ${result.unused_allow_files.join(", ")}\n`,
      );
    }
    if (!result.complete) {
      // Loud, on stderr, and named per file: a partial mirror that reports only
      // a count reads exactly like a complete one.
      write(
        err,
        `memory_ingest: WARNING - the mirror is INCOMPLETE. ${String(result.skipped.length)} file(s) were refused by the secret classifier and are NOT in the vault:\n`,
      );
      for (const skip of result.skipped) {
        write(err, `  refused ${skip.source_path}: ${describeMemorySkipReason(skip)}\n`);
      }
      write(
        err,
        "memory_ingest: remove the sensitive material from those files or keep them outside the mirrored directory, then re-run.\n",
      );
    }
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_ingest", {
      harness: parsed.harness,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
      ...errorCategoryDetail(error),
    });
    write(err, `memory_ingest failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    // F4: zero the owned master even if the audit flush THROWS. The flush is the
    // last consumer that needs the key, but a flush/write error must not skip the
    // fill — so it runs in an inner `finally`, never a bare sequential statement.
    // S1: the shared rotation barrier is released LAST, in its own `finally`, so
    // a flush/zeroing throw can never strand the lease and block rotate-master.
    // The flush above is this verb's final master-derived write, so releasing
    // here is releasing after the last write (AGENTS rule 12).
    try {
      try {
        await boot.auditLog.flush();
      } finally {
        boot.masterKey.fill(0);
      }
    } finally {
      await boot.barrier?.release().catch(() => undefined);
    }
  }
}

export async function runMemoryEmitCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printEmitHelp(out);
    return 0;
  }

  const parsed = parseCommonArgs(args.argv, "memory_emit", err);
  if (!parsed) return 2;

  const approvalChannel = createLocalHumanApprovalInteraction(args.dialogRunner, err);
  if (!approvalChannel) return 1;

  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin, args.observeMasterKey);
  if (!boot) return 1;

  try {
    const decision = await new ApprovalGate(
      await loadPrincipalPolicy(boot.fortressPath),
      boot.baseline,
      approvalChannel,
      boot.auditLog,
    ).evaluate("memory_emit", {
      agent_id: null,
      harness: parsed.harness,
      output_dir: parsed.dir,
      owner_ref: parsed.ownerRef,
    });
    if (!decision.allowed || !decision.approval_audit_id) {
      write(err, "Denied: plaintext memory emission was not approved by the local operator.\n");
      return 1;
    }
    // Write-ahead INTENT, durable before any plaintext file is materialized
    // from the vault. If appendCritical throws, emit aborts without writes.
    // Labelled `_started`: at this point no file exists on disk yet.
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_emit_started",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        approval_audit_id: decision.approval_audit_id,
      },
    });
    const result = parsed.harness === CLAUDE_CODE_MEMORY_HARNESS
      ? await emitClaudeCodeMemoryDirectory(boot.adapter, parsed.dir)
      : await emitCodexMemoryDirectory(boot.adapter, parsed.dir);
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_emit",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        emitted_file_count: result.emitted.length,
        index_present: result.index_present,
        approval_audit_id: decision.approval_audit_id,
      },
    });
    write(
      out,
      `memory_emit: emitted ${String(result.emitted.length)} ${harnessLabel(parsed.harness)} memory files to ${parsed.dir} (index_present: ${result.index_present ? "yes" : "no"})\n`,
    );
    if (!result.index_present) {
      write(
        err,
        `memory_emit: WARNING - emitted tree is missing MEMORY.md and cannot be re-ingested as a ${harnessLabel(parsed.harness)} memory directory.\n`,
      );
    }
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_emit", {
      harness: parsed.harness,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
      ...errorCategoryDetail(error),
    });
    write(err, `memory_emit failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    // F4: zero the owned master even if the audit flush THROWS. The flush is the
    // last consumer that needs the key, but a flush/write error must not skip the
    // fill — so it runs in an inner `finally`, never a bare sequential statement.
    // S1: the shared rotation barrier is released LAST, in its own `finally`, so
    // a flush/zeroing throw can never strand the lease and block rotate-master.
    // The flush above is this verb's final master-derived write, so releasing
    // here is releasing after the last write (AGENTS rule 12).
    try {
      try {
        await boot.auditLog.flush();
      } finally {
        boot.masterKey.fill(0);
      }
    } finally {
      await boot.barrier?.release().catch(() => undefined);
    }
  }
}

export async function runMemoryTranscodeCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printTranscodeHelp(out);
    return 0;
  }
  const parsed = parseTranscodeArgs(args.argv, err);
  if (!parsed) return 2;
  const approvalChannel = createLocalHumanApprovalInteraction(args.dialogRunner, err);
  if (!approvalChannel) return 1;
  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin, args.observeMasterKey);
  if (!boot) return 1;

  try {
    const decision = await new ApprovalGate(
      await loadPrincipalPolicy(boot.fortressPath),
      boot.baseline,
      approvalChannel,
      boot.auditLog,
    ).evaluate("memory_transcode", {
      agent_id: null,
      from_harness: parsed.fromHarness,
      to_harness: parsed.toHarness,
      output_dir: parsed.dir,
      owner_ref: parsed.ownerRef,
    });
    if (!decision.allowed || !decision.approval_audit_id) {
      write(err, "Denied: plaintext memory transcode was not approved by the local operator.\n");
      return 1;
    }
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_transcode_started",
      identity_id: "principal",
      result: "success",
      details: {
        from_harness: parsed.fromHarness,
        to_harness: parsed.toHarness,
        mode: MEMORY_TRANSCODE_MODE,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        approval_audit_id: decision.approval_audit_id,
      },
    });
    const result = await transcodeMemoryDirectory(
      boot.adapter,
      parsed.fromHarness,
      parsed.toHarness,
      parsed.dir,
    );
    try {
      await boot.auditLog.appendCritical({
        layer: "l1",
        operation: "memory_transcode",
        identity_id: "principal",
        result: "success",
        details: {
          archive_id: result.archive_id,
          from_harness: result.from_harness,
          to_harness: result.to_harness,
          mode: result.mode,
          output_dir: parsed.dir,
          owner_ref: parsed.ownerRef,
          source_file_count: result.source_file_count,
          projection_file_count: result.projection_file_count,
          source_set_sha256: result.source_set_sha256,
          projection_set_sha256: result.projection_set_sha256,
          approval_audit_id: decision.approval_audit_id,
        },
      });
    } catch (auditError) {
      write(
        err,
        `memory_transcode completed, but its outcome audit record failed (${errorName(auditError)}). Preserve archive_id ${result.archive_id} and inspect the output before retrying.\n`,
      );
      return 1;
    }
    write(
      out,
      `memory_transcode: projected ${String(result.source_file_count)} ${harnessLabel(parsed.fromHarness)} source files into ${String(result.projection_file_count)} ${harnessLabel(parsed.toHarness)} plaintext files at ${parsed.dir}\n` +
      `memory_transcode: exact source recovery archive_id ${result.archive_id}\n`,
    );
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_transcode", {
      from_harness: parsed.fromHarness,
      to_harness: parsed.toHarness,
      mode: MEMORY_TRANSCODE_MODE,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
      ...errorCategoryDetail(error),
    });
    write(err, `memory_transcode failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    // F4: zero the owned master even if the audit flush THROWS. The flush is the
    // last consumer that needs the key, but a flush/write error must not skip the
    // fill — so it runs in an inner `finally`, never a bare sequential statement.
    // S1: the shared rotation barrier is released LAST, in its own `finally`, so
    // a flush/zeroing throw can never strand the lease and block rotate-master.
    // The flush above is this verb's final master-derived write, so releasing
    // here is releasing after the last write (AGENTS rule 12).
    try {
      try {
        await boot.auditLog.flush();
      } finally {
        boot.masterKey.fill(0);
      }
    } finally {
      await boot.barrier?.release().catch(() => undefined);
    }
  }
}

export async function runMemoryTranscodeRestoreCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printTranscodeRestoreHelp(out);
    return 0;
  }
  const parsed = parseRestoreArgs(args.argv, err);
  if (!parsed) return 2;
  const approvalChannel = createLocalHumanApprovalInteraction(args.dialogRunner, err);
  if (!approvalChannel) return 1;
  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin, args.observeMasterKey);
  if (!boot) return 1;

  try {
    const decision = await new ApprovalGate(
      await loadPrincipalPolicy(boot.fortressPath),
      boot.baseline,
      approvalChannel,
      boot.auditLog,
    ).evaluate("memory_transcode_restore", {
      agent_id: null,
      archive_id: parsed.archiveId,
      output_dir: parsed.dir,
      owner_ref: parsed.ownerRef,
    });
    if (!decision.allowed || !decision.approval_audit_id) {
      write(err, "Denied: plaintext memory transcode restore was not approved by the local operator.\n");
      return 1;
    }
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_transcode_restore_started",
      identity_id: "principal",
      result: "success",
      details: {
        archive_id: parsed.archiveId,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        approval_audit_id: decision.approval_audit_id,
      },
    });
    const result = await restoreMemoryTranscodeArchive(
      boot.adapter,
      parsed.archiveId,
      parsed.dir,
    );
    try {
      await boot.auditLog.appendCritical({
        layer: "l1",
        operation: "memory_transcode_restore",
        identity_id: "principal",
        result: "success",
        details: {
          archive_id: parsed.archiveId,
          source_harness: result.source_harness,
          output_dir: parsed.dir,
          owner_ref: parsed.ownerRef,
          restored_file_count: result.source_file_count,
          source_set_sha256: result.source_set_sha256,
          approval_audit_id: decision.approval_audit_id,
        },
      });
    } catch (auditError) {
      write(
        err,
        `memory_transcode_restore completed, but its outcome audit record failed (${errorName(auditError)}). Inspect ${parsed.dir} before retrying.\n`,
      );
      return 1;
    }
    write(
      out,
      `memory_transcode_restore: restored ${String(result.source_file_count)} exact ${harnessLabel(result.source_harness)} source files to ${parsed.dir}\n`,
    );
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_transcode_restore", {
      archive_id: parsed.archiveId,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
      ...errorCategoryDetail(error),
    });
    write(err, `memory_transcode_restore failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    // F4: zero the owned master even if the audit flush THROWS. The flush is the
    // last consumer that needs the key, but a flush/write error must not skip the
    // fill — so it runs in an inner `finally`, never a bare sequential statement.
    // S1: the shared rotation barrier is released LAST, in its own `finally`, so
    // a flush/zeroing throw can never strand the lease and block rotate-master.
    // The flush above is this verb's final master-derived write, so releasing
    // here is releasing after the last write (AGENTS rule 12).
    try {
      try {
        await boot.auditLog.flush();
      } finally {
        boot.masterKey.fill(0);
      }
    } finally {
      await boot.barrier?.release().catch(() => undefined);
    }
  }
}

interface ParsedVaultArgs {
  readonly dir: string;
  readonly ownerRef: string;
  readonly fortress?: string;
  readonly passphrase?: string;
  readonly passphraseFromStdin: boolean;
}

interface ParsedCommonArgs extends ParsedVaultArgs {
  readonly harness:
    | typeof CLAUDE_CODE_MEMORY_HARNESS
    | typeof CODEX_MEMORY_HARNESS;
}

interface ParsedTranscodeArgs extends ParsedVaultArgs {
  readonly fromHarness: ParsedCommonArgs["harness"];
  readonly toHarness: ParsedCommonArgs["harness"];
}

interface ParsedRestoreArgs extends ParsedVaultArgs {
  readonly archiveId: string;
}

function parseCommonArgs(
  argv: readonly string[],
  command: "memory_ingest" | "memory_emit",
  err: Writable,
): ParsedCommonArgs | null {
  const harness = flagValue([...argv], "--harness");
  const dir = flagValue([...argv], "--dir");
  if (harness !== CLAUDE_CODE_MEMORY_HARNESS && harness !== CODEX_MEMORY_HARNESS) {
    write(err, `${command}: --harness must be "claude-code" or "codex"\n`);
    return null;
  }
  if (dir === undefined || dir.trim().length === 0) {
    write(err, `${command}: --dir is required\n`);
    return null;
  }
  const passphrase = flagValue([...argv], "--passphrase");
  if (passphrase !== undefined) {
    // The secret is already in argv by the time this runs; the warning exists so
    // the operator learns to stop, not to pretend the leak was prevented.
    write(err, PASSPHRASE_ARGV_WARNING);
  }
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // memory ingest/emit operations are a constraint-5 violation.
  const consumedFortress = consumeFlagValue([...argv], "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return null;
  }
  return {
    harness,
    dir,
    ownerRef: flagValue([...argv], "--owner-ref") ?? DEFAULT_OWNER_REF,
    fortress: consumedFortress.value,
    passphrase,
    passphraseFromStdin: hasFlag([...argv], "--passphrase-stdin"),
  };
}

function parseTranscodeArgs(argv: readonly string[], err: Writable): ParsedTranscodeArgs | null {
  const fromHarness = flagValue([...argv], "--from-harness");
  const toHarness = flagValue([...argv], "--to-harness");
  if (
    (fromHarness !== CLAUDE_CODE_MEMORY_HARNESS && fromHarness !== CODEX_MEMORY_HARNESS) ||
    (toHarness !== CLAUDE_CODE_MEMORY_HARNESS && toHarness !== CODEX_MEMORY_HARNESS) ||
    fromHarness === toHarness
  ) {
    write(
      err,
      "memory_transcode: --from-harness and --to-harness must name different values from claude-code or codex\n",
    );
    return null;
  }
  if (flagValue([...argv], "--mode") !== MEMORY_TRANSCODE_MODE) {
    write(err, `memory_transcode: --mode must be "${MEMORY_TRANSCODE_MODE}"\n`);
    return null;
  }
  const common = parseVaultArgs(argv, "memory_transcode", err);
  return common === null ? null : { ...common, fromHarness, toHarness };
}

function parseRestoreArgs(argv: readonly string[], err: Writable): ParsedRestoreArgs | null {
  const archiveId = flagValue([...argv], "--archive-id");
  if (archiveId === undefined || !/^[a-f0-9]{32}$/.test(archiveId)) {
    write(err, "memory_transcode_restore: --archive-id must be the 32-hex id returned by memory_transcode\n");
    return null;
  }
  const common = parseVaultArgs(argv, "memory_transcode_restore", err);
  return common === null ? null : { ...common, archiveId };
}

function parseVaultArgs(
  argv: readonly string[],
  command: string,
  err: Writable,
): ParsedVaultArgs | null {
  const dir = flagValue([...argv], "--dir");
  if (dir === undefined || dir.trim().length === 0) {
    write(err, `${command}: --dir is required\n`);
    return null;
  }
  const passphrase = flagValue([...argv], "--passphrase");
  if (passphrase !== undefined) write(err, PASSPHRASE_ARGV_WARNING);
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // vault operations are a constraint-5 violation.
  const consumedFortress = consumeFlagValue([...argv], "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return null;
  }
  return {
    dir,
    ownerRef: flagValue([...argv], "--owner-ref") ?? DEFAULT_OWNER_REF,
    fortress: consumedFortress.value,
    passphrase,
    passphraseFromStdin: hasFlag([...argv], "--passphrase-stdin"),
  };
}

/**
 * Read one line from stdin as the fortress passphrase.
 *
 * Failure mode to watch for: a caller that passes `--passphrase-stdin` and then
 * never writes to the pipe. That looks like a stuck command rather than a
 * credential problem, so the read is deadline-bounded and an empty result falls
 * through to the normal refusal.
 */
async function readPassphraseFromStdin(stdin: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolvePassphrase) => {
    const rl = createInterface({ input: stdin });
    let settled = false;
    const finish = (value: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      try {
        rl.close();
      } catch {
        // Already closed; the value is what matters.
      }
      resolvePassphrase(value);
    };
    const deadline = setTimeout(() => finish(""), STDIN_READ_DEADLINE_MS);
    rl.once("line", (line) => finish(line));
    rl.once("close", () => finish(""));
    rl.once("error", () => finish(""));
  });
}

interface BootstrappedMemoryFileCommand {
  readonly adapter: SdwMemoryBackendAdapter;
  readonly auditLog: AuditLog;
  readonly baseline: BaselineTracker;
  readonly fortressPath: string;
  /**
   * The 32-byte fortress master key, OWNED by the caller: every verb must
   * `masterKey.fill(0)` in its `finally` AFTER the audit flush (the flush is the
   * last consumer that needs the key to encrypt/sign entries). The adapter,
   * audit log, identity manager, and migration all hold this same buffer, so a
   * single zeroing scrubs every reference.
   */
  readonly masterKey: Uint8Array;
  /**
   * The shared master-rotation barrier held for this write session (S1). Every
   * memory verb here appends audit entries under the master, which are
   * master-derived fortress WRITES, so the barrier is held from unlock and each
   * verb MUST `await barrier.release()` in its `finally` AFTER the final audit
   * flush. Releasing it lets a queued `rotate-master` proceed; holding it makes
   * a concurrent rotation serialize behind this verb rather than commit
   * old-master ciphertext (AGENTS rule 12).
   */
  readonly barrier?: MasterWriteBarrierLease;
}

async function bootstrap(
  args: ParsedVaultArgs,
  env: NodeJS.ProcessEnv,
  err: Writable,
  stdin: NodeJS.ReadableStream,
  observeMasterKey?: (buf: Uint8Array) => void,
): Promise<BootstrappedMemoryFileCommand | null> {
  if (args.fortress !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = args.fortress;
  }

  const stdinPassphrase = args.passphraseFromStdin
    ? await readPassphraseFromStdin(stdin)
    : "";

  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(config.storage_path, "state"));

  // Unlock via the shared local-fortress chokepoint: argv/stdin/env credentials
  // first (the pre-existing compatibility path), then the EXACT-fortress OS
  // keyring so a fresh host whose passphrase is already stored by `protect` can
  // run the first memory verb without re-typing a secret. `config.storage_path`
  // is exact here: `--fortress` was promoted onto SANCTUARY_STORAGE_PATH above,
  // so the keyring lookup is namespaced to THIS fortress. Never generates.
  const unlocked = await unlockLocalFortress({
    storage,
    storagePath: config.storage_path,
    ...(stdinPassphrase.length > 0
      ? { passphraseFromStdin: stdinPassphrase }
      : {}),
    ...(args.passphrase !== undefined
      ? { passphraseFromArgv: args.passphrase }
      : {}),
    env,
    // Every memory verb here appends master-derived audit entries; hold the
    // shared rotation barrier across the whole verb so a concurrent
    // rotate-master serializes or the write fails closed (S1).
    writeIntent: true,
  });
  if (!unlocked.ok) {
    // Fail closed AND diagnosable, with a secret-free remediation. The message
    // never carries credential bytes (CLAUDE.md #6).
    write(err, `Error: could not unlock the fortress: ${unlocked.message}\n`);
    return null;
  }
  const masterKey = unlocked.masterKey;
  observeMasterKey?.(masterKey);
  // Any failure between here and the successful return must zero the owned
  // master before propagating, or a construction throw would leak the live key.
  try {
    const auditLog = new AuditLog(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();
    const identityManager = new IdentityManager(storage, masterKey);
    const loaded = await identityManager.load();
    if (loaded.loaded === 0 || identityManager.getDefault() === undefined) {
      masterKey.fill(0);
      // Release the writeIntent barrier on this early return too: it was acquired
      // before the unlock and is transferred to the caller ONLY on the successful
      // return below, so any bail-out here must release it itself or a stranded
      // shared lease blocks a later rotate-master for the process lifetime (S1).
      // An outer finally cannot own this — the success path must NOT release.
      await unlocked.barrier?.release().catch(() => undefined);
      write(err, "Error: fortress primary identity is unavailable.\n");
      return null;
    }
    const fortressId = fortressIdFromStoragePath(config.storage_path);
    const signingHandle = createPrimaryMemoryProvenanceSigningHandleResolver(identityManager, masterKey);
    const signerPublicKey = createPrimaryMemoryProvenancePublicKeyResolver(identityManager);
    const migration = new SdwMemoryProvenanceMigration({
      storage,
      masterKey,
      fortressId,
      ownerRef: args.ownerRef,
      resolvePrimarySigningHandle: signingHandle,
      resolveSignerPublicKey: signerPublicKey,
    });
    const adapter = new SdwMemoryBackendAdapter({
      storage,
      masterKey,
      fortressId,
      ownerRef: args.ownerRef,
      resolvePrimarySigningHandle: signingHandle,
      resolveSignerPublicKey: signerPublicKey,
      resolveMemoryIntegrityState: () => migration.getState(),
    });
    return {
      adapter,
      auditLog,
      baseline,
      fortressPath: config.storage_path,
      masterKey,
      ...(unlocked.barrier !== undefined ? { barrier: unlocked.barrier } : {}),
    };
  } catch (e) {
    masterKey.fill(0);
    // The construction failed AFTER the write barrier was acquired; release it
    // so a stranded lease does not block a later rotate-master (S1).
    await unlocked.barrier?.release().catch(() => undefined);
    throw e;
  }
}

async function appendFailure(
  auditLog: AuditLog,
  operation:
    | "memory_ingest"
    | "memory_emit"
    | "memory_transcode"
    | "memory_transcode_restore",
  details: Record<string, unknown>,
): Promise<void> {
  try {
    await auditLog.appendCritical({
      layer: "l1",
      operation: `${operation}_denied`,
      identity_id: "system",
      result: "failure",
      details,
    });
  } catch {
    // Preserve the original operator-visible error. The command still returns
    // non-zero and flushes whatever audit state is available in finally.
  }
}

function harnessLabel(
  harness: typeof CLAUDE_CODE_MEMORY_HARNESS | typeof CODEX_MEMORY_HARNESS,
): string {
  return harness === CLAUDE_CODE_MEMORY_HARNESS ? "Claude Code" : "Codex";
}

/**
 * Rung-1 F2: name which detector refused a file and where, in plain English,
 * instead of the constant "classifier_reject" category alone. Class and
 * location only, never the matched content. The reason-text lookup itself is
 * sdwClassifierReasonText (sdw/errors.ts), shared with the memory_ingest MCP
 * tool result so the two surfaces cannot drift on what a detector id means.
 */
function describeMemorySkipReason(skip: {
  readonly reason: string;
  readonly detector?: string;
  readonly line?: number;
}): string {
  const reasonText = sdwClassifierReasonText(skip.reason, skip.detector);
  return skip.line === undefined ? reasonText : `${reasonText} (line ${String(skip.line)})`;
}

function printIngestHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_ingest --harness=<claude-code|codex> --dir <path> [options]

Manually mirror Claude Code or Codex memory files into the encrypted SDW vault.
Source files remain plaintext and untouched; this command does not sync or watch.

Options:
  --harness <name>       Required: claude-code or codex.
  --dir <path>           Harness memory directory to read. Codex also accepts
                         the parent Codex home containing memories/.
  --allow-file <path>    Repeatable. Ingest this ONE file as-is even if the
                         secret classifier would refuse it: the source
                         filename exactly as this command names it in its
                         WARNING/refused output (e.g. Codex raw_memories.md,
                         not memories/raw_memories.md), never a glob or a
                         directory. Records an audited override naming the
                         path and the detector that would have fired. A path
                         the classifier never refused is reported as unused,
                         and an unknown path is an error. There is no flag
                         that waives the classifier for every file.
  --owner-ref <id>       SDW owner_ref scope (default: fleet-self).
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Fortress passphrase. Visible in the process list to
                         any local user; prefer SANCTUARY_PASSPHRASE or
                         --passphrase-stdin.
  --help, -h             Show this help.

Credential precedence: --passphrase-stdin, then --passphrase, then
SANCTUARY_PASSPHRASE, then SANCTUARY_RECOVERY_KEY, then this fortress's stored
passphrase in the OS keyring (the exact-fortress unwrap, so a host where
'sanctuary protect' already stored the passphrase opens the fortress with no
secret supplied). A locked keyring is reported; a passphrase is never generated.
`,
  );
}

function printEmitHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_emit --harness=<claude-code|codex> --dir <path> [options]

Manually emit Claude Code or Codex memory files from the encrypted SDW vault
into an operator-named output directory. Existing files are never overwritten.

Options:
  --harness <name>       Required: claude-code or codex.
  --dir <path>           Output directory for emitted plaintext files.
  --owner-ref <id>       SDW owner_ref scope (default: fleet-self).
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Fortress passphrase. Visible in the process list to
                         any local user; prefer SANCTUARY_PASSPHRASE or
                         --passphrase-stdin.
  --help, -h             Show this help.
`,
  );
}

function printTranscodeHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_transcode --from-harness=<claude-code|codex> --to-harness=<claude-code|codex> --mode=reversible --dir <path> [options]

Manually create a plaintext native projection in the other harness format and
a versioned encrypted archive for exact source recovery. This is not sync.

Options:
  --from-harness <name> Source harness already mirrored into the SDW vault.
  --to-harness <name>   Different destination harness format.
  --mode reversible     Required frozen transcode contract.
  --dir <path>           Empty output directory; existing files are refused.
  --owner-ref <id>       SDW owner_ref scope (default: fleet-self).
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Visible in the process list; prefer the environment or stdin.
  --help, -h             Show this help.
`,
  );
}

function printTranscodeRestoreHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_transcode_restore --archive-id <id> --dir <path> [options]

Restore exact plaintext source files from a completed encrypted transcode
archive into an empty output directory. This is not sync.

Options:
  --archive-id <id>      Opaque id returned by memory_transcode.
  --dir <path>           Empty output directory; existing files are refused.
  --owner-ref <id>       SDW owner_ref scope (default: fleet-self).
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Visible in the process list; prefer the environment or stdin.
  --help, -h             Show this help.
`,
  );
}

function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const cause = errorCauseMessage(errorCause(error));
  return cause === undefined ? message : `${message}; cause: ${cause}`;
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "Error";
}

function errorCategoryDetail(error: unknown): Record<string, string> {
  if (!(error instanceof SdwValidationError)) return {};
  const cause = errorCauseMessage(errorCause(error));
  return {
    error_category: error.category,
    ...(cause === undefined ? {} : { error_cause: cause }),
  };
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
