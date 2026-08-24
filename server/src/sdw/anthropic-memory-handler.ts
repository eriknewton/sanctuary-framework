/**
 * Anthropic Memory-tool -> SDW handler (LOCAL spike, synthetic data only).
 *
 * The Anthropic Memory tool (`memory_20250818`) is client-side: the developer
 * implements the storage backend, and "encrypted files" is an explicitly
 * blessed backend (see the first-principles verdict, Crux 4). This handler
 * routes the six Memory-tool file operations onto the SHIPPED
 * `MemoryBackendAdapter`, so an Agent-SDK worker's `/memories` would land in
 * the operator's sovereign vault (encrypted at rest, secret-gated, audited).
 *
 * SCOPE (deliberately constrained - see the scope adversarial round): this is
 * a LOCAL handler exercised by tests with SYNTHETIC data. It makes NO Anthropic
 * API call. A real worker round-trip transmits operator memory across the API
 * boundary (MUST-NEVER #1) and is a separate, Erik-present follow-up. Nothing
 * here imports the Anthropic SDK; the six-op contract shape is modeled locally
 * so the mapping can be proven without a dependency or a network call.
 *
 * THE HONEST MISMATCH (Crux 4 - surfaced, not papered over): the adapter is
 * insert + delete only with NO in-place mutation. The Memory tool's mutating
 * ops therefore do not map one-to-one:
 *   - `str_replace` and mid-file `insert` are realized as delete + re-insert,
 *     which is NON-ATOMIC (a concurrent reader can see a gap; a concurrent
 *     writer can fill it). The handler reports `mutation_strategy:
 *     "delete_then_insert"` on these ops so the non-atomicity is visible.
 *   - `rename` is read + insert-new + delete-old, also non-atomic. The handler
 *     reports `mutation_strategy: "insert_then_delete"` for that path.
 * This is the lost-update gap the verdict's per-agent-append + curated-
 * promotion design closes; a single agent's own scope is single-writer, so the
 * non-atomic window is harmless there, but the handler never pretends the op is
 * atomic.
 *
 * A `/memories/<name>` path maps to a passage whose `passage_id` is derived
 * from `<name>` (SDW-identifier-safe). Files are flat passages; this spike does
 * not model nested directories.
 */

import { createHash } from "node:crypto";
import type { MemoryBackendAdapter, MemoryPassage } from "./adapters/memory-backend.js";
import { isSdwIdentifier } from "./grammar.js";
import { anthropicMemoryToolIngress } from "./memory-provenance-ingress.js";
import type { CurrentMemoryAgentId } from "./memory-provenance-ingress.js";

/** The six Memory-tool commands (the stable file-shaped contract). */
export type AnthropicMemoryCommand =
  | { readonly command: "view"; readonly path: string }
  | { readonly command: "create"; readonly path: string; readonly file_text: string }
  | {
      readonly command: "str_replace";
      readonly path: string;
      readonly old_str: string;
      readonly new_str: string;
    }
  | {
      readonly command: "insert";
      readonly path: string;
      readonly insert_line: number;
      readonly insert_text: string;
    }
  | { readonly command: "delete"; readonly path: string }
  | { readonly command: "rename"; readonly old_path: string; readonly new_path: string };

export interface AnthropicMemoryResult {
  readonly ok: boolean;
  /** Tool-result text the model would see (or an error string). */
  readonly content: string;
  /**
   * When a mutating op had to be realized as a non-atomic sequence on the
   * insert/delete-only backend, this names the strategy so the caller (and a
   * reader of the audit) sees the mismatch honestly.
   */
  readonly mutation_strategy?: "delete_then_insert" | "insert_then_delete";
  readonly error_code?: string;
}

const MAX_MEMORY_FILE_TEXT_BYTES = 1024 * 1024;

/**
 * Persistable taint for memory-tool-originated content. The model supplies this
 * text, so keep the provenance conservative; the classifier still gates writes.
 */
const MEMORY_TOOL_TAINT = "user_content" as const;

/**
 * Map a `/memories/<name>` path to an SDW-identifier-safe passage id. The raw
 * name is hashed so arbitrary path text always yields a valid, stable id; the
 * mapping is deterministic so the same path round-trips to the same passage.
 */
export function passageIdForPath(path: string): string {
  const digest = createHash("sha256").update(path, "utf8").digest("hex").slice(0, 40);
  const id = `am.${digest}`;
  // Defensive: the constructed id always satisfies the SDW identifier grammar.
  if (!isSdwIdentifier(id)) {
    throw new Error("internal: constructed passage id is not an SDW identifier");
  }
  return id;
}

function fail(error_code: string, content: string): AnthropicMemoryResult {
  return { ok: false, content, error_code };
}

/**
 * Apply one Memory-tool command against the sovereign passage adapter. The
 * adapter enforces the custody invariants it owns (write-gate secret rejection,
 * encryption at rest). NOTE: this synthetic spike does NOT itself write audit
 * entries for its ops; tool-level audit is wired when the handler is registered
 * into the live server (see Company_Brain_Registration_Followups). This handler
 * only translates the file contract onto passage ops and surfaces the
 * insert/delete-only mismatch.
 */
export async function applyAnthropicMemoryCommand(
  adapter: MemoryBackendAdapter,
  command: AnthropicMemoryCommand,
  currentAgentId?: CurrentMemoryAgentId,
): Promise<AnthropicMemoryResult> {
  // Snapshot before any asynchronous read/write in the command. The opaque
  // context retains this ingress observation even if the environment changes.
  const observedAgentId = currentAgentId?.();
  const ingressAgent = () => observedAgentId;
  switch (command.command) {
    case "view": {
      const passage = await safeGet(adapter, command.path);
      if (passage === null) return fail("not_found", "Memory not found");
      return { ok: true, content: passage.text };
    }

    case "create": {
      if (!fitsMemoryFileCap(command.file_text)) {
        return fail("too_large", "Memory file is too large");
      }
      const id = passageIdForPath(command.path);
      // create is write-new; an existing path is a conflict (the adapter throws
      // duplicate_passage). The handler surfaces it rather than silently
      // overwriting (no silent lost update).
      const existing = await safeGet(adapter, command.path);
      if (existing !== null) {
        return fail("exists", "Memory already exists; use str_replace");
      }
      try {
        await adapter.insertPassage(
          { passage_id: id, text: command.file_text,
            provenanceContext: anthropicMemoryToolIngress(ingressAgent, "user_content") },
          MEMORY_TOOL_TAINT,
        );
      } catch (error) {
        return fail("write_rejected", describeWriteError(error));
      }
      return { ok: true, content: "Created memory" };
    }

    case "str_replace": {
      const passage = await safeGet(adapter, command.path);
      if (passage === null) return fail("not_found", "Memory not found");
      if (!passage.text.includes(command.old_str)) {
        return fail("no_match", "old_str not found");
      }
      // Use a function replacer so new_str is inserted LITERALLY. A plain
      // string replacement makes String.prototype.replace interpret $-patterns
      // ($&, $`, $', $$, $1) in new_str, which would silently corrupt stored
      // content (the original is then securely overwritten -> irreversible).
      const next = passage.text.replace(command.old_str, () => command.new_str);
      // NON-ATOMIC on the insert/delete-only backend: delete then re-insert.
      return mutateByReplace(adapter, command.path, next, ingressAgent);
    }

    case "insert": {
      const passage = await safeGet(adapter, command.path);
      if (passage === null) return fail("not_found", "Memory not found");
      const lines = passage.text.split("\n");
      const at = command.insert_line;
      if (!Number.isInteger(at) || at < 0 || at > lines.length) {
        return fail("bad_line", `insert_line ${at} out of range`);
      }
      lines.splice(at, 0, command.insert_text);
      // NON-ATOMIC: mid-file insert requires mutation -> delete then re-insert.
      return mutateByReplace(adapter, command.path, lines.join("\n"), ingressAgent);
    }

    case "delete": {
      const id = passageIdForPath(command.path);
      const deleted = await adapter.deletePassage(id);
      if (!deleted) return fail("not_found", "Memory not found");
      return { ok: true, content: "Deleted memory" };
    }

    case "rename": {
      const passage = await safeGet(adapter, command.old_path);
      if (passage === null) return fail("not_found", "Memory not found");
      const destExisting = await safeGet(adapter, command.new_path);
      if (destExisting !== null) {
        return fail("exists", "Memory already exists");
      }
      const newId = passageIdForPath(command.new_path);
      // NON-ATOMIC: read old -> insert new -> delete old.
      try {
        await adapter.insertPassage(
          { passage_id: newId, text: passage.text,
            provenanceContext: anthropicMemoryToolIngress(ingressAgent, "user_content") },
          MEMORY_TOOL_TAINT,
        );
      } catch (error) {
        return fail("write_rejected", describeWriteError(error));
      }
      const oldDeleted = await adapter.deletePassage(passageIdForPath(command.old_path));
      if (!oldDeleted) return fail("old_delete_failed", "Rename could not remove original memory");
      return {
        ok: true,
        content: "Renamed memory",
        mutation_strategy: "insert_then_delete",
      };
    }

    default: {
      // Exhaustiveness: an unknown command is rejected, never silently ignored.
      return fail("unknown_command", "Unknown memory command");
    }
  }
}

async function safeGet(
  adapter: MemoryBackendAdapter,
  path: string,
): Promise<MemoryPassage | null> {
  return adapter.getPassage(passageIdForPath(path));
}

/**
 * Realize a content change on the insert/delete-only backend as delete + insert.
 * This is the explicit non-atomic mapping for str_replace / mid-file insert.
 */
async function mutateByReplace(
  adapter: MemoryBackendAdapter,
  path: string,
  nextText: string,
  currentAgentId?: CurrentMemoryAgentId,
): Promise<AnthropicMemoryResult> {
  if (!fitsMemoryFileCap(nextText)) {
    return fail("too_large", "Memory file is too large");
  }
  const id = passageIdForPath(path);
  await adapter.deletePassage(id);
  try {
    await adapter.insertPassage({ passage_id: id, text: nextText,
      provenanceContext: anthropicMemoryToolIngress(currentAgentId, "user_content") }, MEMORY_TOOL_TAINT);
  } catch (error) {
    // The old content is already deleted; surface the failure honestly rather
    // than leaving a half-applied edit silently.
    return fail("write_rejected_after_delete", describeWriteError(error));
  }
  return {
    ok: true,
    content: "Updated memory",
    mutation_strategy: "delete_then_insert",
  };
}

function fitsMemoryFileCap(text: string): boolean {
  return Buffer.byteLength(text, "utf8") <= MAX_MEMORY_FILE_TEXT_BYTES;
}

function describeWriteError(_error: unknown): string {
  // The adapter's write-gate rejects secrets (classifier_reject) and duplicate
  // ids; keep those categories out of model-visible content.
  return "write rejected";
}
