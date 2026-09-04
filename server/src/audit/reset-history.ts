/**
 * Sanctuary MCP Server — Reset-history continuity (v1.0.2 item a)
 *
 * Closes the audit-log continuity gap left by `sanctuary reset-passphrase
 * --nuke`. The reset path destroys the encrypted audit log along with the
 * rest of the fortress state, then writes a plaintext `<storagePath>/.reset-history.log`
 * marker (NDJSON, append-only, one JSON object per reset) before exiting.
 *
 * On the next boot of the fortress (whether the MCP server in `index.ts` or
 * the standalone dashboard), this module:
 *
 *   1. Reads the marker file if present.
 *   2. Parses every NDJSON line into a {@link ResetHistoryMarker}.
 *   3. Computes a SHA-256 hash of the file's raw bytes.
 *   4. Appends one `fortress_recovered_from_reset` audit entry per marker
 *      to the freshly-rebuilt audit log, embedding the marker fields and
 *      the file hash so a verifier can prove the entry corresponds to a
 *      real reset event.
 *   5. Awaits {@link AuditLog.flush} so the entries reach disk.
 *   6. Deletes the marker (one-shot consumption) so subsequent boots are
 *      no-ops.
 *
 * The marker is unsigned plaintext by construction — `reset-passphrase
 * --nuke` runs BEFORE the new fortress exists, so there is no key to sign
 * with. The continuity property therefore comes from the marker hash
 * being committed to the (encrypted) audit log under the new fortress's
 * master key, not from per-entry signatures.
 *
 * No Concordia or Verascore imports (non-dependency principle).
 */

import { readFile, rm, access, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { hashToString } from "../core/hashing.js";
import { stringToBytes } from "../core/encoding.js";
import type { AuditLog } from "../operational/audit-log.js";

/** Filename of the reset-history marker, sibling to the fortress storage path. */
export const RESET_HISTORY_FILENAME = ".reset-history.log";

/** Audit-log operation name used for recovered-from-reset entries. */
export const RECOVERED_FROM_RESET_OPERATION = "fortress_recovered_from_reset";

/**
 * Recovery modes that may appear in the marker. This array is the SINGLE
 * SOURCE OF TRUTH for the valid `recovery_mode` set: the boot reader (this
 * module's parser) and the marker writer (`RecoveryMode` in
 * `server/src/cli/reset-passphrase.ts`, which imports the type below) share
 * it, so a mode the writer can persist can never be a mode the reader
 * rejects. A writer/reader schema split here bricks the next server boot —
 * a rejected marker throws `ResetHistoryMalformedError` and `index.ts`
 * refuses to start (AGENTS rule 11: writer and reader consume one schema).
 * Must match `RecoveryMode` in server/src/cli/reset-passphrase.ts.
 */
export const RESET_HISTORY_RECOVERY_MODES = [
  "shares",
  "guardian",
  "nuke",
  "recovery-key",
] as const;

/** Recovery modes that may appear in the marker; matches reset-passphrase.ts. */
export type ResetHistoryRecoveryMode =
  (typeof RESET_HISTORY_RECOVERY_MODES)[number];

/**
 * Shape of one NDJSON line in `.reset-history.log` as written by
 * `reset-passphrase --nuke`. Future modes (`shares`, `guardian`) will write
 * the same shape.
 */
export interface ResetHistoryMarker {
  started_at: string;
  completed_at: string;
  recovery_mode: ResetHistoryRecoveryMode;
  fortress_name: string;
  storage_path: string;
  keychain_cleared: boolean;
}

/** Result of parsing the marker file. */
export interface ParsedResetHistory {
  markers: ResetHistoryMarker[];
  /** SHA-256 of the raw file bytes, base64url-encoded. */
  markerHash: string;
}

/** Result of consuming the marker. */
export interface ConsumeResult {
  emitted: number;
  markerHash?: string;
  /** Path of the marker that was consumed (whether emitted, no-op, or absent). */
  markerPath: string;
}

/**
 * Thrown when `.reset-history.log` exists but cannot be parsed. The fortress
 * boot path catches this and surfaces a clear remediation message rather
 * than silently swallowing the parse failure.
 */
export class ResetHistoryMalformedError extends Error {
  constructor(
    public readonly markerPath: string,
    public readonly lineNumber: number,
    public readonly cause: unknown
  ) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    super(
      `Reset-history marker at ${markerPath} is malformed at line ${lineNumber}: ${reason}.\n` +
        `Inspect the file and either correct the JSON or delete it manually before re-running.`
    );
    this.name = "ResetHistoryMalformedError";
  }
}

// ── Pure parser ─────────────────────────────────────────────────────

/**
 * Parse the marker file content. Each non-empty line MUST be a JSON object
 * matching {@link ResetHistoryMarker}. Trailing newline tolerated. Blank
 * lines tolerated. Any other deviation throws {@link ResetHistoryMalformedError}.
 *
 * Computes a SHA-256 of the raw bytes (not the parsed markers) so a
 * verifier holding the original marker file out-of-band can recompute the
 * hash and confirm the audit entries correspond to that exact file.
 *
 * Pure function — no I/O — for unit testing.
 */
export function parseResetHistory(
  content: string,
  markerPath: string
): ParsedResetHistory {
  const markerHash = hashToString(stringToBytes(content));
  const markers: ResetHistoryMarker[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    if (raw.trim().length === 0) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new ResetHistoryMalformedError(markerPath, i + 1, err);
    }
    markers.push(coerceMarker(parsed, markerPath, i + 1));
  }
  return { markers, markerHash };
}

function coerceMarker(
  raw: unknown,
  markerPath: string,
  lineNumber: number
): ResetHistoryMarker {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ResetHistoryMalformedError(
      markerPath,
      lineNumber,
      new Error("expected a JSON object")
    );
  }
  const obj = raw as Record<string, unknown>;
  const required: Array<keyof ResetHistoryMarker> = [
    "started_at",
    "completed_at",
    "recovery_mode",
    "fortress_name",
    "storage_path",
    "keychain_cleared",
  ];
  for (const field of required) {
    if (!(field in obj)) {
      throw new ResetHistoryMalformedError(
        markerPath,
        lineNumber,
        new Error(`missing required field "${field}"`)
      );
    }
  }
  if (typeof obj.started_at !== "string")
    throw typed(markerPath, lineNumber, "started_at", "string");
  if (typeof obj.completed_at !== "string")
    throw typed(markerPath, lineNumber, "completed_at", "string");
  if (typeof obj.fortress_name !== "string")
    throw typed(markerPath, lineNumber, "fortress_name", "string");
  if (typeof obj.storage_path !== "string")
    throw typed(markerPath, lineNumber, "storage_path", "string");
  if (typeof obj.keychain_cleared !== "boolean")
    throw typed(markerPath, lineNumber, "keychain_cleared", "boolean");
  // Validate against the single source-of-truth set so the reader accepts
  // exactly what the writer can persist (AGENTS rule 11); a hand-maintained
  // disjunction here is the drift that bricks boot after a new mode ships.
  if (
    typeof obj.recovery_mode !== "string" ||
    !(RESET_HISTORY_RECOVERY_MODES as readonly string[]).includes(
      obj.recovery_mode
    )
  ) {
    throw new ResetHistoryMalformedError(
      markerPath,
      lineNumber,
      new Error(
        `recovery_mode must be one of ${RESET_HISTORY_RECOVERY_MODES.join("|")} (got ${JSON.stringify(obj.recovery_mode)})`
      )
    );
  }
  return {
    started_at: obj.started_at,
    completed_at: obj.completed_at,
    recovery_mode: obj.recovery_mode as ResetHistoryRecoveryMode,
    fortress_name: obj.fortress_name,
    storage_path: obj.storage_path,
    keychain_cleared: obj.keychain_cleared,
  };
}

function typed(
  markerPath: string,
  lineNumber: number,
  field: string,
  expected: string
): ResetHistoryMalformedError {
  return new ResetHistoryMalformedError(
    markerPath,
    lineNumber,
    new Error(`field "${field}" must be a ${expected}`)
  );
}

// ── Stateful helper ────────────────────────────────────────────────

export interface ConsumeOptions {
  /**
   * Fortress storage root (sibling of the `state/` directory). The marker
   * lives at `<storagePath>/.reset-history.log` per `reset-passphrase.ts`.
   */
  storagePath: string;
  auditLog: AuditLog;
}

/**
 * Process the reset-history marker if present. Returns the number of audit
 * entries appended; zero when no marker exists (the common path).
 *
 * One-shot: the marker is deleted only after the audit log has flushed
 * successfully. If flush fails, the marker is left in place so a retry on
 * the next boot can re-emit; this is preferable to losing the continuity
 * record entirely. Duplicates on retry are bounded by the marker being
 * single-file (one boot path consumes it; subsequent boots find no file).
 *
 * Throws {@link ResetHistoryMalformedError} on parse failure. Callers
 * should refuse to continue fortress boot in that case rather than silently
 * skip the entry.
 */
export async function consumeResetHistoryMarker(
  options: ConsumeOptions
): Promise<ConsumeResult> {
  const markerPath = join(options.storagePath, RESET_HISTORY_FILENAME);
  const consumedPath = markerPath + ".consumed";

  // If a prior consumption succeeded but the marker delete failed, the
  // `.consumed` sentinel will still exist. Skip re-emission and clean up.
  if (await fileExists(consumedPath)) {
    await rm(markerPath, { force: true });
    await rm(consumedPath, { force: true });
    return { emitted: 0, markerPath };
  }

  if (!(await fileExists(markerPath))) {
    return { emitted: 0, markerPath };
  }
  const content = await readFile(markerPath, "utf-8");
  const { markers, markerHash } = parseResetHistory(content, markerPath);
  if (markers.length === 0) {
    // Empty or whitespace-only file. Treat as a no-op rather than an
    // error: the marker writer always appends a trailing newline, so an
    // empty file is structurally valid.
    await rm(markerPath, { force: true });
    return { emitted: 0, markerHash, markerPath };
  }
  for (let i = 0; i < markers.length; i++) {
    const marker = markers[i]!;
    await options.auditLog.append("l2", RECOVERED_FROM_RESET_OPERATION, "system", {
      reset_at_started: marker.started_at,
      reset_at_completed: marker.completed_at,
      recovery_mode: marker.recovery_mode,
      fortress_name: marker.fortress_name,
      reset_storage_path: marker.storage_path,
      keychain_cleared: marker.keychain_cleared,
      reset_marker_hash: markerHash,
      reset_marker_index: i,
      reset_marker_total: markers.length,
    });
  }
  await options.auditLog.flush();
  // Write `.consumed` sentinel BEFORE deleting the marker. If the process
  // crashes between these two operations, the next boot sees `.consumed`
  // and skips re-emission (idempotent). Owner-only (0600) from the first
  // byte: this is a direct fortress-root child, and every root-child writer
  // creates owner-only so a live file-grant traverse ACE never exposes it by
  // name (see the FORTRESS-DIR TRAVERSAL note in file-grant/fs-ops.ts).
  await writeFile(consumedPath, "", { mode: 0o600 });
  await rm(markerPath, { force: true });
  await rm(consumedPath, { force: true });
  return { emitted: markers.length, markerHash, markerPath };
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
