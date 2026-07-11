/**
 * Durable EXPORT CURSOR: the last audit-chain sequence the streaming exporter has
 * confirmed delivered.
 *
 * WHY A CURSOR EXISTS: the streaming consumer (`./stream.ts`) reads the WHOLE
 * verified audit chain each run (that is how `AuditLog.streamVerifiedChain`
 * works). Without a persisted resume point, every run would re-map and re-deliver
 * the entire history (a re-send storm). The cursor records how far delivery has
 * caught up, so a run only forwards entries whose chain sequence is STRICTLY
 * ABOVE it.
 *
 * THE CRASH/RESTART CONTRACT (the load-bearing safety property):
 *   - The cursor is persisted ONLY AFTER a batch (or a whole clean pass) is
 *     confirmed delivered by the fail-loud sink. So a crash can only ever leave
 *     the cursor BEHIND the true delivered frontier, never ahead of it.
 *   - Behind-the-frontier is the SAFE direction: the un-acknowledged entries are
 *     simply re-scanned and re-delivered on the next run. This yields
 *     at-least-once with NO GAP. The only cost of a lost cursor write is that the
 *     already-delivered tail of one batch may be re-sent (a collector dedupes on
 *     event identity); it is never a silent drop and never a skipped entry.
 *   - Because a lost write is fail-safe, the persist does an atomic
 *     write-temp-then-rename (so a reader never sees a half-written cursor file)
 *     but does not need an fsync barrier: losing the write degrades to re-send,
 *     not to a gap.
 *
 * The cursor file lives under the OPERATOR-owned fortress `state/` directory. The
 * store is an injected interface so `./stream.ts` and its tests never touch a real
 * `~/.sanctuary` path (an in-memory store keeps the tests hermetic).
 */

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

/**
 * Sentinel meaning "nothing exported yet". Strictly below every real chain
 * sequence (sequences are non-negative), so a first run forwards from the start.
 */
export const EXPORT_CURSOR_START = -1;

/** The on-disk filename under `<fortress>/state/`. */
export const EXPORT_CURSOR_FILENAME = "cortex-export-cursor.json";

/** A durable place to read/advance the export resume point. */
export interface ExportCursorStore {
  /**
   * The last confirmed-delivered chain sequence, or {@link EXPORT_CURSOR_START}
   * when nothing has been exported yet. A missing/absent cursor reads as the
   * start sentinel (fail-safe: re-scan from the beginning, never skip).
   */
  read(): Promise<number>;
  /**
   * Durably record a new resume point. MUST be called only after the events up to
   * and including `sequence` are confirmed delivered. Advancing is monotonic; a
   * caller never moves the cursor backward.
   */
  write(sequence: number): Promise<void>;
}

/** Shape persisted to the cursor file. Versioned so a later change is additive. */
interface PersistedCursor {
  schema: "sanctuary.enforcement-export-cursor.v1";
  /** Last confirmed-delivered chain sequence. */
  last_sequence: number;
}

const CURSOR_SCHEMA = "sanctuary.enforcement-export-cursor.v1" as const;

/**
 * A filesystem-backed cursor under `<fortress>/state/cortex-export-cursor.json`.
 * Reads fail-safe to the start sentinel on a missing or unreadable/garbage file
 * (re-scan, never skip); writes are atomic (temp + rename).
 */
export class FileExportCursorStore implements ExportCursorStore {
  private readonly filePath: string;

  constructor(fortressPath: string) {
    this.filePath = join(fortressPath, "state", EXPORT_CURSOR_FILENAME);
  }

  async read(): Promise<number> {
    let rawText: string;
    try {
      rawText = await readFile(this.filePath, "utf8");
    } catch (err) {
      const code =
        err instanceof Error && "code" in err ? (err as NodeJS.ErrnoException).code : undefined;
      // No cursor yet is the documented first-run state. Any OTHER read error is
      // ALSO treated as "start from the beginning": re-scanning the chain is the
      // fail-safe direction (at-least-once), never a skipped entry.
      if (code === "ENOENT") return EXPORT_CURSOR_START;
      return EXPORT_CURSOR_START;
    }
    try {
      const parsed = JSON.parse(rawText) as unknown;
      if (
        parsed &&
        typeof parsed === "object" &&
        (parsed as PersistedCursor).schema === CURSOR_SCHEMA &&
        typeof (parsed as PersistedCursor).last_sequence === "number" &&
        Number.isInteger((parsed as PersistedCursor).last_sequence) &&
        (parsed as PersistedCursor).last_sequence >= EXPORT_CURSOR_START
      ) {
        return (parsed as PersistedCursor).last_sequence;
      }
    } catch {
      // A garbage cursor file is treated as "no cursor" (re-scan, fail-safe).
    }
    return EXPORT_CURSOR_START;
  }

  async write(sequence: number): Promise<void> {
    const payload: PersistedCursor = { schema: CURSOR_SCHEMA, last_sequence: sequence };
    const dir = dirname(this.filePath);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    // Atomic replace so a concurrent reader never observes a half-written file.
    const tmpPath = join(dir, `.${EXPORT_CURSOR_FILENAME}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
    await writeFile(tmpPath, `${JSON.stringify(payload)}\n`, { mode: 0o600 });
    await rename(tmpPath, this.filePath);
  }
}
