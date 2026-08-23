/**
 * Shared classifier-override decision for the Rung-1 memory-file ingest
 * `--allow-file` / `allow_files` escape hatch (point 3, ratified 2026-08-22:
 * Wiki/decisions/rung1-classifier-refusal-ux-explain-never-redact-2026-08-22.md).
 *
 * Both the Claude Code and Codex memory-file adapters screen every source
 * entry through the SAME MemoryBackendAdapter.screenPassage/putPassages gate
 * and must resolve each entry to exactly one of four outcomes: accepted
 * (classifier had nothing to say), skipped (refused, and either not
 * allow-listed or refused for a reason the allow-file cannot waive), overridden
 * (allow-listed AND refused specifically by the classifier, ingested with the
 * refusal metadata retained), or allow-file-unused (allow-listed but never
 * refused, so nothing was waived). A hand-duplicated copy of this decision per
 * adapter is exactly the two-copies-drift class AGENTS.md rule 5 warns about
 * (one copy could forget the `classifier_reject`-only scoping and let an
 * allow-file waive a grammar or size refusal too), so it lives here once and
 * both adapters call it.
 */

import type { PersistableTaint } from "../provenance.js";
import { mintClassifierOverrideAuthorization } from "../write-gate.js";
import type {
  MemoryBackendAdapter,
  MemoryPassageInput,
} from "./memory-backend.js";
import { passageContentHash } from "./sdw-memory-backend.js";

/**
 * DISTINCT local audit operation string for the Rung-1 memory-file ingest
 * classifier-override lifecycle (point 3, ratified 2026-08-22:
 * Wiki/decisions/rung1-classifier-refusal-ux-explain-never-redact-2026-08-22.md).
 * Lives alongside the decision this op name records (screenMemoryFileEntries'
 * `overridden` outcome, below) so the two cannot drift apart.
 *
 * Sole source for this op name, imported by both `cli/memory-file.ts` and
 * `sdw/memory-file-tools.ts` (cross-file pin: keep both in sync with this
 * constant, never re-type the string literal) so the CLI and MCP surfaces
 * cannot drift on what the override audit record is called.
 *
 * This is a LOCAL string, not a widened shared enum: `AuditLog.operation` is
 * `string`, and adding a new local op here fans out to nothing else.
 */
export const MEMORY_INGEST_CLASSIFIER_OVERRIDE = "memory_ingest_classifier_override" as const;

/** One source file the write gate refused, named so the operator can act on it. */
export interface MemoryFileSkip {
  readonly source_path: string;
  /** SdwValidationError category, e.g. "classifier_reject". */
  readonly reason: string;
  readonly detail: string;
  /** SdwValidationError.detector; populated only when reason is "classifier_reject". */
  readonly detector?: string;
  /** SdwValidationError.line; the 1-based line the detector matched, when known. */
  readonly line?: number;
}

/**
 * One source file the classifier would have refused, ingested anyway because
 * the operator named it on an explicit --allow-file / allow_files list. Same
 * shape as a skip (the refusal metadata is retained, never discarded), just
 * routed to `accepted` instead of `skipped`.
 */
export type MemoryFileOverride = MemoryFileSkip;

export interface MemoryFileScreenOutcome {
  readonly accepted: readonly MemoryPassageInput[];
  readonly skipped: readonly MemoryFileSkip[];
  readonly overridden: readonly MemoryFileOverride[];
  /**
   * Allow-listed source paths that were never a classifier refusal (either
   * never refused at all, or refused for a reason the allow-file cannot waive)
   * -- surfaced so a stale or mistargeted allow-file entry is visible rather
   * than a silent no-op.
   */
  readonly unused_allow_files: readonly string[];
}

/**
 * Confirm every allow-listed path names a real source entry before any
 * screening runs, so a typo'd or stale path is a loud error, never a silently
 * ignored no-op (Rung-1 point 3 build item 5).
 */
export function assertAllowFilesKnown(
  entrySourcePaths: readonly string[],
  allowFiles: ReadonlySet<string>,
): void {
  const known = new Set(entrySourcePaths);
  const unknown = [...allowFiles].filter((path) => !known.has(path)).sort();
  if (unknown.length > 0) {
    throw new Error(
      `--allow-file path not found in the source directory: ${unknown.join(", ")}`,
    );
  }
}

/**
 * Screen every entry and resolve accept / skip / override for each. Exact
 * match only: `allowFiles` is compared with `Set.has` against each entry's own
 * `sourcePath`, which the two adapters only ever populate with a bare filename
 * they themselves discovered in the source directory, so this can never match
 * a glob, a directory, or a path the operator did not enumerate.
 */
export function screenMemoryFileEntries(
  adapter: MemoryBackendAdapter,
  entries: readonly { readonly sourcePath: string; readonly input: MemoryPassageInput }[],
  taint: PersistableTaint,
  allowFiles: ReadonlySet<string>,
): MemoryFileScreenOutcome {
  assertAllowFilesKnown(
    entries.map((entry) => entry.sourcePath),
    allowFiles,
  );

  const accepted: MemoryPassageInput[] = [];
  const skipped: MemoryFileSkip[] = [];
  const overridden: MemoryFileOverride[] = [];
  const usedAllowFiles = new Set<string>();

  for (const entry of entries) {
    const screen = adapter.screenPassage(entry.input, taint, true);
    if (screen.ok) {
      accepted.push(entry.input);
      continue;
    }
    // The allow-file waives ONLY a classifier_reject. Any other refusal
    // category (grammar, size, identifier) still skips even when the path is
    // allow-listed: the override is scoped to the secret classifier alone,
    // never a general "ingest this file no matter what" switch.
    if (allowFiles.has(entry.sourcePath) && screen.category === "classifier_reject") {
      usedAllowFiles.add(entry.sourcePath);
      overridden.push({
        source_path: entry.sourcePath,
        reason: screen.category,
        detail: screen.message,
        detector: screen.detector,
        line: screen.line,
      });
      // Mint the ROOT authorization bound to THIS passage's exact text (HIGH-C1
      // fix round): preparePassage (sdw-memory-backend.ts) re-verifies this
      // against the same hash before deriving any per-record authorization
      // from it, so pairing this token with different content never verifies.
      const authorization = mintClassifierOverrideAuthorization(
        passageContentHash(entry.input.text),
      );
      accepted.push({ ...entry.input, classifierOverrideAuthorization: authorization });
      continue;
    }
    skipped.push({
      source_path: entry.sourcePath,
      reason: screen.category,
      detail: screen.message,
      detector: screen.detector,
      line: screen.line,
    });
  }

  const unusedAllowFiles = [...allowFiles].filter((path) => !usedAllowFiles.has(path)).sort();
  return { accepted, skipped, overridden, unused_allow_files: unusedAllowFiles };
}
