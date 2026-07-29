/**
 * Fleet control plane PR-3: the OPERATOR-VISIBLE DOWNGRADE LOG.
 *
 * Fail-closing to Community silently strips paid console-management features
 * (nodes drop out of the central roster). That is safe for SECURITY (every
 * node's wall stays up) but it is NOT acceptable UX to do it invisibly: the
 * operator must be able to answer, in one click, "these N nodes left the console
 * because the plan lapsed/expired/was revoked - their walls are still up." This
 * module is that record: an append-only, master-MAC'd, operator-readable log of
 * every tier/cap TRANSITION with its reason and the affected node ids.
 *
 * ── WHY MASTER-MAC'd, APPEND-ONLY ──────────────────────────────────────────
 * The log is tamper-EVIDENT under the master (mirror {@link FLEET_ACTIVATION_META_KEY}):
 * a disk-write attacker cannot forge or silently truncate an entry without the
 * master. It is append-only in intent (each transition adds one entry). The
 * stored array is BOUNDED to the most-recent {@link MAX_DOWNGRADE_LOG_ENTRIES}
 * so it can never grow without limit; older entries roll off. A dropped entry is
 * caught by the MAC (the whole array is MAC'd), so truncation is tamper-evident
 * up to the retained window.
 *
 * ── NO SECRETS ──────────────────────────────────────────────────────────────
 * An entry carries node IDS + a reason + tier/cap numbers. It NEVER carries key
 * material, a raw license token, or a passphrase (constraint 6). Node ids are
 * federation identifiers already surfaced on the roster.
 *
 * ── FAIL-CLOSED / NON-BLOCKING ──────────────────────────────────────────────
 * The log is OBSERVABILITY. Appending is best-effort: a failed log append must
 * NEVER block or reverse the actual cap transition (the transition already
 * fail-closed correctly). A tampered/unreadable log reads as EMPTY-with-a-warning
 * rather than throwing, so a trashed log file cannot brick the read path.
 */

import type { StorageBackend } from "../storage/interface.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import { canonicalJson } from "../audit/chain.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
  constantTimeEqual,
} from "../core/encoding.js";
import type { FleetCapReason } from "./fleet-cap.js";

/** `_meta` key holding the master-MAC'd operator-visible downgrade log. */
export const DOWNGRADE_LOG_META_KEY = "fleet-downgrade-log-v1";

const DOWNGRADE_LOG_MARKER = "__sanctuary_fleet_downgrade_log_v1";
/** Fresh MAC domain for the log record (distinct from every other MAC domain). */
const DOWNGRADE_LOG_MAC_DOMAIN = "sanctuary.fleet.downgrade-log.v1\n";
/** HKDF purpose label for the log MAC key (distinct from all others). */
const DOWNGRADE_LOG_MAC_PURPOSE = "fleet-downgrade-log-mac";

/**
 * Retention bound: the log keeps the most-recent N transitions. A control-plane
 * fortress transitions rarely (activation, expiry, renewal, revocation), so 200
 * is generous headroom while keeping the MAC'd blob small and bounded.
 */
export const MAX_DOWNGRADE_LOG_ENTRIES = 200;

/**
 * The kind of transition. `downgrade` = paid capacity dropped (fewer nodes in
 * console / lapse to Community). `upgrade` = paid capacity restored/raised
 * (renewal, activation). `grandfather_capture` = the one-time auto-capture of a
 * never-activated over-cap fleet's baseline. `revocation_list_unreadable` = the
 * stored revocation list failed to authenticate (surfaced, not acted on).
 */
export type DowngradeTransitionKind =
  | "downgrade"
  | "upgrade"
  | "grandfather_capture"
  | "revocation_list_unreadable";

/** One immutable transition entry. All fields are operator-readable; no secrets. */
export interface DowngradeLogEntry {
  /** ISO-8601 time the transition was recorded. */
  at: string;
  /** The transition kind. */
  kind: DowngradeTransitionKind;
  /** Tier before the transition (e.g. "team"). */
  fromTier: string;
  /** Tier after the transition (e.g. "community"). */
  toTier: string;
  /** Max central-console nodes before (null = unlimited). */
  fromMaxNodes: number | null;
  /** Max central-console nodes after (null = unlimited). */
  toMaxNodes: number | null;
  /** Why the fleet resolved to the new cap (the fail-closed provenance). */
  reason: FleetCapReason;
  /**
   * The node ids that LEFT the central console on this transition (their walls
   * stay up). Empty on an upgrade or a no-node-change transition.
   */
  droppedNodeIds: string[];
  /**
   * Operator-facing one-line explanation, e.g. "Team plan expired; 3 nodes left
   * the console. Their Castle Wall protection is unaffected. Renew to restore
   * central management." Never contains secrets.
   */
  message: string;
}

/** The MAC'd payload: the bounded, ordered (oldest-first) entry list. */
interface DowngradeLogData {
  entries: DowngradeLogEntry[];
}

function downgradeLogMac(master: Uint8Array, data: DowngradeLogData): Uint8Array {
  const macKey = derivePurposeKey(master, DOWNGRADE_LOG_MAC_PURPOSE);
  const mac = hmacSha256(
    macKey,
    stringToBytes(DOWNGRADE_LOG_MAC_DOMAIN + canonicalJson(data)),
  );
  macKey.fill(0);
  return mac;
}

/** Structural validity of one stored entry (a corrupt entry fails the whole read). */
function isValidEntry(value: unknown): value is DowngradeLogEntry {
  if (typeof value !== "object" || value === null) return false;
  const e = value as Record<string, unknown>;
  return (
    typeof e.at === "string" &&
    typeof e.kind === "string" &&
    (e.kind === "downgrade" ||
      e.kind === "upgrade" ||
      e.kind === "grandfather_capture" ||
      e.kind === "revocation_list_unreadable") &&
    typeof e.fromTier === "string" &&
    typeof e.toTier === "string" &&
    (e.fromMaxNodes === null || typeof e.fromMaxNodes === "number") &&
    (e.toMaxNodes === null || typeof e.toMaxNodes === "number") &&
    typeof e.reason === "string" &&
    Array.isArray(e.droppedNodeIds) &&
    e.droppedNodeIds.every((id) => typeof id === "string") &&
    typeof e.message === "string"
  );
}

/**
 * The result of reading the downgrade log. `readable` is false when the stored
 * record was present but failed to authenticate (tampered/wrong-key); the caller
 * surfaces the corruption but still shows an (empty) log rather than throwing.
 */
export interface DowngradeLogRead {
  entries: DowngradeLogEntry[];
  readable: boolean;
}

/**
 * Read + authenticate the downgrade log, NEVER throwing.
 *  - absent -> `{ entries: [], readable: true }` (no transitions yet).
 *  - valid  -> `{ entries, readable: true }` (oldest-first).
 *  - invalid (tampered/wrong-key/malformed/unreadable) -> `{ entries: [],
 *    readable: false }` (corruption surfaced; never a throw, never a brick).
 */
export async function readDowngradeLog(
  storage: StorageBackend,
  master: Uint8Array,
): Promise<DowngradeLogRead> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read("_meta", DOWNGRADE_LOG_META_KEY);
  } catch {
    return { entries: [], readable: false };
  }
  if (!raw) return { entries: [], readable: true };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    return { entries: [], readable: false };
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as Record<string, unknown>)[DOWNGRADE_LOG_MARKER] !== true
  ) {
    return { entries: [], readable: false };
  }
  const obj = parsed as Record<string, unknown>;
  const data = obj.data as { entries?: unknown } | undefined;
  const mac = obj.mac;
  if (
    !data ||
    typeof data !== "object" ||
    !Array.isArray(data.entries) ||
    !data.entries.every(isValidEntry) ||
    typeof mac !== "string"
  ) {
    return { entries: [], readable: false };
  }
  const entries = data.entries as DowngradeLogEntry[];
  const fullData: DowngradeLogData = { entries };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    return { entries: [], readable: false };
  }
  if (!constantTimeEqual(provided, downgradeLogMac(master, fullData))) {
    return { entries: [], readable: false };
  }
  return { entries, readable: true };
}

/**
 * Append one transition entry to the downgrade log, re-MAC'ing the bounded
 * result. Best-effort observability: the caller MUST NOT let a throw here reverse
 * the actual cap transition (wrap the call in a try/catch that ignores failures).
 *
 * When the currently-stored log is UNREADABLE (tampered), we do NOT trust or
 * extend the corrupt array; we start a fresh log whose first entry is the new
 * transition. This keeps the append path total (a trashed file cannot wedge
 * future logging) while the corruption itself is surfaced by
 * {@link readDowngradeLog} returning `readable: false` until the next write.
 *
 * The stored array is bounded to the most-recent {@link MAX_DOWNGRADE_LOG_ENTRIES}.
 */
export async function appendDowngradeLog(
  storage: StorageBackend,
  master: Uint8Array,
  entry: DowngradeLogEntry,
): Promise<void> {
  if (!isValidEntry(entry)) {
    throw new Error("appendDowngradeLog: refusing to append a malformed entry");
  }
  const existing = await readDowngradeLog(storage, master);
  // A corrupt existing log is not extended; start fresh with this entry.
  const base = existing.readable ? existing.entries : [];
  const next = [...base, entry];
  const bounded =
    next.length > MAX_DOWNGRADE_LOG_ENTRIES
      ? next.slice(next.length - MAX_DOWNGRADE_LOG_ENTRIES)
      : next;
  const data: DowngradeLogData = { entries: bounded };
  const record = {
    [DOWNGRADE_LOG_MARKER]: true,
    data,
    mac: toBase64url(downgradeLogMac(master, data)),
  };
  await storage.write(
    "_meta",
    DOWNGRADE_LOG_META_KEY,
    stringToBytes(JSON.stringify(record)),
  );
}
