/**
 * Durable, MASTER-KEY-AUTHENTICATED EXPORT CURSOR: the last audit-chain sequence
 * the streaming exporter has confirmed delivered, bound to the chain identity.
 *
 * WHY A CURSOR EXISTS: the streaming consumer (`./stream.ts`) reads the WHOLE
 * verified audit chain each run (that is how `AuditLog.streamVerifiedChain`
 * works). Without a persisted resume point, every run would re-map and re-deliver
 * the entire history (a re-send storm). The cursor records how far delivery has
 * caught up, so a run only forwards entries whose chain sequence is STRICTLY
 * ABOVE it.
 *
 * WHY IT IS AUTHENTICATED (the tamper class this closes): every OTHER link in the
 * enforcement-export rail is tamper-evident (the chain is hash-linked + MAC'd, the
 * mapping is closed, the sink fails loud). The cursor WAS the one un-authenticated
 * link: a run trusted any well-formed cursor value. A poisoned high cursor
 * (`last_sequence: 999999999`) made a run forward ZERO events, advance nothing,
 * and emit NOTHING — the off-box console silently went blind to every denial. So:
 *   - The persisted record is MAC'd with a purpose key derived from the fortress
 *     master key (the SAME construction the audit rotation/head anchors use). A
 *     hand-written or tampered cursor fails the MAC → it is DISCARDED, loudly (the
 *     streamer audits + stderrs the reset), never trusted for its value.
 *   - The record BINDS the sequence to the chain identity via the `entry_hash` at
 *     that sequence. An audit-store wipe+recreate (or a rotation) that regrows a
 *     DIFFERENT chain carries a different hash at the same sequence, so a stale
 *     high cursor cannot silently skip the new low sequences (the streamer detects
 *     the mismatch and re-scans from the start). This mirrors the observe fold
 *     watermark's chain-identity binding.
 *   - A pre-authentication (v1, un-MAC'd) record is RECOGNIZED but treated as
 *     UNAUTHENTICATED → discarded loudly → re-scan. It is never silently trusted.
 *
 * The head-clamp and chain-identity checks live in the streamer (`./stream.ts`),
 * which is where the verified chain head is known; the MAC lives here (this is
 * where persistence happens). Both are belt-and-suspenders: the MAC rejects a
 * forged value; the clamp/identity checks reject a legitimately-MAC'd but stale
 * value that no longer matches THIS chain.
 *
 * THE CRASH/RESTART CONTRACT (the load-bearing safety property, UNCHANGED):
 *   - The cursor is persisted ONLY AFTER a batch (or a whole clean pass) is
 *     confirmed delivered by the fail-loud sink. So a crash can only ever leave
 *     the cursor BEHIND the true delivered frontier, never ahead of it.
 *   - Behind-the-frontier is the SAFE direction: the un-acknowledged entries are
 *     simply re-scanned and re-delivered on the next run. This yields
 *     at-least-once with NO GAP. The only cost of a lost cursor write is that the
 *     already-delivered tail of one batch may be re-sent (a collector dedupes on
 *     event identity); it is never a silent drop and never a skipped entry.
 *   - A DISCARDED cursor (any authentication/identity failure) falls back to the
 *     SAME safe direction — the start sentinel, i.e. a full re-scan — never a
 *     silent zero-forward. The fallback is always LOUD (see `ExportCursorReset`).
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

import { derivePurposeKey } from "../../core/key-derivation.js";
import { hmacSha256 } from "../../core/hashing.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  constantTimeEqual,
} from "../../core/encoding.js";
import { canonicalJson } from "../../audit/chain.js";

/**
 * Sentinel meaning "nothing exported yet". Strictly below every real chain
 * sequence (sequences are non-negative), so a first run forwards from the start.
 */
export const EXPORT_CURSOR_START = -1;

/** The on-disk filename under `<fortress>/state/`. */
export const EXPORT_CURSOR_FILENAME = "cortex-export-cursor.json";

/**
 * Purpose label for the master-key-derived cursor MAC key. Distinct from every
 * other purpose string (e.g. the audit anchors' `audit-rotation-anchor`), so the
 * cursor MAC key is domain-separated from every other derived key by construction.
 */
const CURSOR_MAC_PURPOSE = "enforcement-export-cursor";

/**
 * Domain prefix mixed into the MAC input, mirroring the audit anchors'
 * `<schema>.vN\n` convention — belt-and-suspenders domain separation on top of
 * the distinct purpose key.
 */
const CURSOR_MAC_DOMAIN = "sanctuary.enforcement-export-cursor.v2\n";

/** The AUTHENTICATED on-disk schema (envelope with `data` + master-key `mac`). */
const CURSOR_SCHEMA_V2 = "sanctuary.enforcement-export-cursor.v2" as const;

/** The durable resume state: how far delivery has caught up, PLUS the chain anchor. */
export interface ExportCursorState {
  /**
   * The last confirmed-delivered chain sequence, or {@link EXPORT_CURSOR_START}
   * when nothing has been exported yet.
   */
  sequence: number;
  /**
   * The `entry_hash` of the chain entry AT `sequence` — the chain-identity anchor
   * that binds this cursor to a specific chain/epoch. `null` ONLY at the start
   * sentinel (there is no entry to bind to). A wipe+recreate that regrows a
   * different chain carries a different hash here, so the streamer can detect the
   * identity break and re-scan rather than silently skip the new prefix.
   */
  entryHash: string | null;
}

/** The start-sentinel state (nothing exported yet; no chain identity to bind). */
export const EXPORT_CURSOR_START_STATE: ExportCursorState = {
  sequence: EXPORT_CURSOR_START,
  entryHash: null,
};

/**
 * Why {@link ExportCursorStore.read} DISCARDED a persisted cursor and fell back to
 * the start sentinel. EVERY value here is a LOUD signal (the streamer surfaces it
 * as an `enforcement_export_cursor_reset` audit record + a stderr warning), never
 * a silent zero-forward. A reset re-scans from the beginning (fail-safe,
 * at-least-once); it NEVER skips.
 */
export interface ExportCursorReset {
  reason:
    /** A non-ENOENT read error (EACCES/EIO/…). Previously reset SILENTLY; a silent
     * re-send storm no one can see is exactly the failure this surface prevents. */
    | "cursor_unreadable"
    /** The cursor file is not parseable JSON. */
    | "cursor_corrupt"
    /** No authenticated (v2) envelope: a legacy v1 record OR a hand-written bare
     * cursor. Recognized, never trusted for its value. */
    | "cursor_unauthenticated"
    /** An authenticated envelope whose `data` fields are the wrong type/range. */
    | "cursor_malformed"
    /** MAC present but does not verify → tampered, forged, or written under a
     * different master key. */
    | "cursor_mac_invalid";
  /** Human-readable specifics for the audit record + stderr line (no secrets). */
  detail: string;
}

/** The outcome of a cursor read: the trusted state, plus a loud reset reason if any. */
export interface ExportCursorReadResult {
  /**
   * The TRUSTED resume state. On ANY reset this is the start sentinel
   * ({@link EXPORT_CURSOR_START_STATE}): re-scan from the beginning, never skip.
   */
  state: ExportCursorState;
  /**
   * Non-null when a persisted cursor was DISCARDED. The caller MUST surface it
   * loudly (audit + stderr) — a reset is a full re-send / a formerly-blind
   * console, never a silent event.
   */
  reset: ExportCursorReset | null;
}

/** A durable place to read/advance the export resume point. */
export interface ExportCursorStore {
  /**
   * Read the durable resume state. A missing cursor (first run) reads as the start
   * sentinel with NO reset. Any unreadable/corrupt/UNAUTHENTICATED/tampered cursor
   * reads as the start sentinel WITH a loud {@link ExportCursorReset} the caller
   * must surface (fail-safe: re-scan from the beginning, never skip).
   */
  read(): Promise<ExportCursorReadResult>;
  /**
   * Durably record a new resume point + its chain-identity anchor. MUST be called
   * only after the events up to and including `state.sequence` are confirmed
   * delivered. Advancing is monotonic; a caller never moves the cursor backward.
   */
  write(state: ExportCursorState): Promise<void>;
}

/** Shape persisted to the cursor file (authenticated envelope). */
interface PersistedCursorV2 {
  schema: typeof CURSOR_SCHEMA_V2;
  /** The MAC'd payload: last confirmed-delivered sequence + its chain-identity hash. */
  data: { last_sequence: number; entry_hash: string | null };
  /** base64url master-key MAC over `CURSOR_MAC_DOMAIN + canonicalJson(data)`. */
  mac: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * A filesystem-backed, master-key-AUTHENTICATED cursor under
 * `<fortress>/state/cortex-export-cursor.json`. Writes are atomic (temp + rename)
 * and MAC'd; reads verify the MAC + fail-safe to the start sentinel (WITH a loud
 * reset reason) on any missing/unreadable/unauthenticated/tampered file.
 */
export class FileExportCursorStore implements ExportCursorStore {
  private readonly filePath: string;
  private readonly macKey: Uint8Array;

  /**
   * @param fortressPath the fortress root (the cursor lives under `state/`).
   * @param masterKey the 32-byte fortress master key. `derivePurposeKey` throws
   *   unless it is exactly 32 bytes, so an UN-KEYED authenticated store can never
   *   silently exist (there is no un-authenticated fallback constructor).
   */
  constructor(fortressPath: string, masterKey: Uint8Array) {
    this.filePath = join(fortressPath, "state", EXPORT_CURSOR_FILENAME);
    this.macKey = derivePurposeKey(masterKey, CURSOR_MAC_PURPOSE);
  }

  /** Domain-separated master-key MAC over the cursor `data` record. */
  private macBytes(data: { last_sequence: number; entry_hash: string | null }): Uint8Array {
    return hmacSha256(this.macKey, stringToBytes(CURSOR_MAC_DOMAIN + canonicalJson(data)));
  }

  async read(): Promise<ExportCursorReadResult> {
    let rawText: string;
    try {
      rawText = await readFile(this.filePath, "utf8");
    } catch (err) {
      const code =
        err instanceof Error && "code" in err ? (err as NodeJS.ErrnoException).code : undefined;
      // No cursor yet is the documented first-run state: start, NO reset (silent).
      if (code === "ENOENT") return { state: { ...EXPORT_CURSOR_START_STATE }, reset: null };
      // Any OTHER read error (EACCES/EIO/…) also fail-safes to start — but LOUDLY:
      // a silent reset here is a full re-send storm no operator can see, and it can
      // mask a permission/mount fault that keeps re-sending forever.
      return {
        state: { ...EXPORT_CURSOR_START_STATE },
        reset: {
          reason: "cursor_unreadable",
          detail: `${code ?? "read error"}: ${err instanceof Error ? err.message : String(err)}`,
        },
      };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      return {
        state: { ...EXPORT_CURSOR_START_STATE },
        reset: { reason: "cursor_corrupt", detail: "cursor file is not valid JSON" },
      };
    }

    // Must be an authenticated v2 envelope. A legacy v1 record (schema
    // "…cursor.v1", no MAC) or a bare hand-written cursor falls here → treated as
    // UNAUTHENTICATED, never trusted for its value.
    if (
      !isRecord(parsed) ||
      parsed.schema !== CURSOR_SCHEMA_V2 ||
      !isRecord(parsed.data) ||
      typeof parsed.mac !== "string"
    ) {
      const found =
        isRecord(parsed) && typeof parsed.schema === "string" ? parsed.schema : "(none)";
      return {
        state: { ...EXPORT_CURSOR_START_STATE },
        reset: {
          reason: "cursor_unauthenticated",
          detail: `cursor is not an authenticated v2 envelope (schema=${found})`,
        },
      };
    }

    const data = parsed.data;
    const lastSequence = data.last_sequence;
    const entryHash = data.entry_hash;
    if (
      typeof lastSequence !== "number" ||
      !Number.isInteger(lastSequence) ||
      lastSequence < EXPORT_CURSOR_START ||
      !(entryHash === null || typeof entryHash === "string")
    ) {
      return {
        state: { ...EXPORT_CURSOR_START_STATE },
        reset: {
          reason: "cursor_malformed",
          detail: "cursor data fields are the wrong type or out of range",
        },
      };
    }

    let provided: Uint8Array;
    try {
      provided = fromBase64url(parsed.mac);
    } catch {
      return {
        state: { ...EXPORT_CURSOR_START_STATE },
        reset: { reason: "cursor_mac_invalid", detail: "cursor MAC is not valid base64url" },
      };
    }
    if (
      !constantTimeEqual(
        provided,
        this.macBytes({ last_sequence: lastSequence, entry_hash: entryHash }),
      )
    ) {
      return {
        state: { ...EXPORT_CURSOR_START_STATE },
        reset: {
          reason: "cursor_mac_invalid",
          detail: "cursor MAC does not verify (tampered, forged, or wrong master key)",
        },
      };
    }

    return { state: { sequence: lastSequence, entryHash }, reset: null };
  }

  async write(state: ExportCursorState): Promise<void> {
    const data = { last_sequence: state.sequence, entry_hash: state.entryHash };
    const envelope: PersistedCursorV2 = {
      schema: CURSOR_SCHEMA_V2,
      data,
      mac: toBase64url(this.macBytes(data)),
    };
    const dir = dirname(this.filePath);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    // Atomic replace so a concurrent reader never observes a half-written file.
    const tmpPath = join(
      dir,
      `.${EXPORT_CURSOR_FILENAME}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`,
    );
    await writeFile(tmpPath, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
    await rename(tmpPath, this.filePath);
  }
}
