/**
 * The one IPC schema between the server and the local job worker, used by
 * both sides on send and on receive. Must match the message handling in
 * worker-client.ts and worker-entry.ts; 1b adds job messages here.
 *
 * No message carries record text, a result or a free-form error string. Key
 * bytes travel only in `init` (the two derived store keys) and in a granted
 * `authority_reply` (one namespace key per ref of that job).
 */
import { serialize } from "node:v8";
import { isAbsolute } from "node:path";
import { CROSS_PROCESS_LOCK_TIMEOUT_MS } from "../storage/cross-process-lock.js";
import { parseBindingDescriptor, type LocalBindingDescriptor } from "./binding.js";
import { INSTRUCTION_MAX_CHARS, SOURCE_REFS_MAX } from "./limits.js";
import { KIB, LOCAL_STORE_KEY_BYTES, SECOND_MS, isRequestId } from "./store-record.js";

// A 1b job record is at most 32 refs, a 500-character instruction and 32
// keys of 32 bytes, far under 64 KiB; no message carries record text or a result.
export const IPC_MESSAGE_MAX_BYTES = 64 * KIB;
// Passed to the worker as --max-old-space-size.
export const WORKER_HEAP_MAX_MB = 512;
// Twice the cross-process lock acquire timeout, since init opens the stores under their locks.
export const WORKER_READY_TIMEOUT_MS = 2 * CROSS_PROCESS_LOCK_TIMEOUT_MS;
// Respawn backoff doubles from one second, capped at one minute; it resets
// after a worker stays ready for WORKER_RESPAWN_MAX_MS.
export const WORKER_RESPAWN_INITIAL_MS = 1 * SECOND_MS;
export const WORKER_RESPAWN_MAX_MS = 60 * SECOND_MS;
// Linux PATH_MAX, the longest path a storage root can name.
const STORAGE_ROOT_MAX_LENGTH = 4_096;
// One reported name or exec argument; a loader path is at most a PATH_MAX path.
const STATUS_ITEM_MAX_LENGTH = STORAGE_ROOT_MAX_LENGTH;
// The heap flag and at most two loader imports, with room for Node's own flags.
const STATUS_LIST_MAX_ITEMS = 64;

/** The only environment names the worker inherits; no `SANCTUARY_*` and no proxy variable. */
export const WORKER_ENV_NAMES = ["PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL"] as const;

/** Named lifecycle states, shared by the client and the worker's status reply. */
export const WORKER_STATES = ["state_SPAWNING", "state_READY", "state_DEAD", "state_BACKOFF"] as const;
export type WorkerState = (typeof WORKER_STATES)[number];

/** Closed fault kinds; a fault never carries a message string. */
export const WORKER_FAULT_KINDS = ["init_invalid", "store_open", "housekeeping", "uncaught"] as const;
export type WorkerFaultKind = (typeof WORKER_FAULT_KINDS)[number];

// Linux NAME_MAX: one encoded storage path component is at most 255 bytes.
export const STORAGE_NAME_MAX_CHARS = 255;
// A seat is an identity id or the fixed unbound seat; 256 characters covers every id format.
export const SEAT_MAX_CHARS = 256;
// An instruction is at most 500 code points of at most 2 UTF-16 units each.
const INSTRUCTION_MAX_UNITS = 2 * INSTRUCTION_MAX_CHARS;
// An Ed25519 public key is 32 bytes.
const WRITER_PUBLIC_KEY_BYTES = 32;
// A writer table row lists one identity's current key and its rotation history; the IPC byte cap bounds the table.
const WRITER_KEYS_PER_ROW_MAX = 1_024;
const WRITER_ROWS_MAX = 1_024;

/** One record reference of a local task. */
export interface LocalTaskRef {
  namespace: string;
  key: string;
}

/** One identity's authenticated writer public keys, as `openStateEntry` resolves a kid. */
export interface WriterKeyRow {
  kid: string;
  public_keys: Uint8Array[];
}

/** Closed causes for a refused authority reply. Must match the job_refused causes in summarize-job.ts. */
export const AUTHORITY_REFUSAL_CAUSES = [
  "unarmed",
  "binding_absent",
  "epoch_changed",
  "assurance_mismatch",
  "not_loopback",
  "identity_mismatch",
  "uncovered",
  "request_unknown",
  "writer_table_too_large",
] as const;
export type AuthorityRefusalCause = (typeof AUTHORITY_REFUSAL_CAUSES)[number];

/** The server's answer to `authority_request`; must match LocalAuthority.reply in authority.ts. */
export type AuthorityReply =
  | {
      type: "authority_reply";
      request_id: string;
      outcome: "granted";
      descriptor: LocalBindingDescriptor;
      keys: Uint8Array[];
      writers: WriterKeyRow[];
    }
  | { type: "authority_reply"; request_id: string; outcome: "refused"; cause: AuthorityRefusalCause };

export type ParentMessage =
  | { type: "init"; storage_root: string; oplog_key: Uint8Array; results_key: Uint8Array }
  | AuthorityReply
  | { type: "shutdown" };

export type WorkerMessage =
  | { type: "ready" }
  | { type: "authority_request"; request_id: string }
  | { type: "status"; state: WorkerState; env_names: string[]; exec_argv: string[]; queue_depth: number }
  | { type: "fault"; kind: WorkerFaultKind };

export class WorkerProtocolError extends Error {
  constructor() {
    super("local worker message refused");
    this.name = "WorkerProtocolError";
  }
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function isStoreKey(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array && value.length === LOCAL_STORE_KEY_BYTES;
}

function isBoundedStringList(value: unknown, maxItems: number, maxLength: number): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maxItems &&
    value.every((item) => typeof item === "string" && item.length <= maxLength)
  );
}

/** Parse a parent-to-worker message; null for anything outside the schema. */
export function parseParentMessage(value: unknown): ParentMessage | null {
  const message = record(value);
  if (message === null) return null;
  if (message.type === "shutdown") return exactKeys(message, ["type"]) ? { type: "shutdown" } : null;
  if (message.type === "init") {
    if (
      !exactKeys(message, ["type", "storage_root", "oplog_key", "results_key"]) ||
      typeof message.storage_root !== "string" ||
      message.storage_root.length > STORAGE_ROOT_MAX_LENGTH ||
      !isAbsolute(message.storage_root) ||
      !isStoreKey(message.oplog_key) ||
      !isStoreKey(message.results_key)
    ) {
      return null;
    }
    return {
      type: "init",
      storage_root: message.storage_root,
      oplog_key: message.oplog_key,
      results_key: message.results_key,
    };
  }
  if (message.type === "authority_reply") return parseAuthorityReply(message);
  return null;
}

function isRef(value: unknown): value is LocalTaskRef {
  const ref = record(value);
  return (
    ref !== null &&
    exactKeys(ref, ["namespace", "key"]) &&
    typeof ref.namespace === "string" &&
    ref.namespace.length > 0 &&
    ref.namespace.length <= STORAGE_NAME_MAX_CHARS &&
    typeof ref.key === "string" &&
    ref.key.length > 0 &&
    ref.key.length <= STORAGE_NAME_MAX_CHARS
  );
}

/** A ref list as the job carries it: 1 to SOURCE_REFS_MAX refs of bounded names. */
export function isRefList(value: unknown): value is LocalTaskRef[] {
  return Array.isArray(value) && value.length >= 1 && value.length <= SOURCE_REFS_MAX && value.every(isRef);
}

/** An instruction as the job carries it, bounded in UTF-16 units; the tool bounds it in code points. */
export function isInstructionText(value: unknown): value is string {
  return typeof value === "string" && value.length <= INSTRUCTION_MAX_UNITS;
}

function isWriterRow(value: unknown): value is WriterKeyRow {
  const row = record(value);
  return (
    row !== null &&
    exactKeys(row, ["kid", "public_keys"]) &&
    typeof row.kid === "string" &&
    row.kid.length > 0 &&
    row.kid.length <= SEAT_MAX_CHARS &&
    Array.isArray(row.public_keys) &&
    row.public_keys.length <= WRITER_KEYS_PER_ROW_MAX &&
    row.public_keys.every((key) => key instanceof Uint8Array && key.length === WRITER_PUBLIC_KEY_BYTES)
  );
}

function parseAuthorityReply(message: Record<string, unknown>): AuthorityReply | null {
  if (!isRequestId(message.request_id)) return null;
  if (message.outcome === "refused") {
    if (!exactKeys(message, ["type", "request_id", "outcome", "cause"])) return null;
    if (!AUTHORITY_REFUSAL_CAUSES.some((cause) => cause === message.cause)) return null;
    return { type: "authority_reply", request_id: message.request_id, outcome: "refused", cause: message.cause as AuthorityRefusalCause };
  }
  if (message.outcome !== "granted" || !exactKeys(message, ["type", "request_id", "outcome", "descriptor", "keys", "writers"])) return null;
  const descriptor = parseBindingDescriptor(message.descriptor);
  if (
    descriptor === null ||
    !Array.isArray(message.keys) ||
    message.keys.length < 1 ||
    message.keys.length > SOURCE_REFS_MAX ||
    !message.keys.every(isStoreKey) ||
    !Array.isArray(message.writers) ||
    message.writers.length > WRITER_ROWS_MAX ||
    !message.writers.every(isWriterRow)
  ) {
    return null;
  }
  return {
    type: "authority_reply",
    request_id: message.request_id,
    outcome: "granted",
    descriptor,
    keys: [...(message.keys as Uint8Array[])],
    writers: (message.writers as WriterKeyRow[]).map((row) => ({ kid: row.kid, public_keys: [...row.public_keys] })),
  };
}

/** Parse a worker-to-parent message; null for anything outside the schema. */
export function parseWorkerMessage(value: unknown): WorkerMessage | null {
  const message = record(value);
  if (message === null) return null;
  switch (message.type) {
    case "ready":
      return exactKeys(message, ["type"]) ? { type: "ready" } : null;
    case "authority_request":
      return exactKeys(message, ["type", "request_id"]) && isRequestId(message.request_id)
        ? { type: "authority_request", request_id: message.request_id }
        : null;
    case "fault":
      return exactKeys(message, ["type", "kind"]) && WORKER_FAULT_KINDS.some((kind) => kind === message.kind)
        ? { type: "fault", kind: message.kind as WorkerFaultKind }
        : null;
    case "status": {
      if (
        !exactKeys(message, ["type", "state", "env_names", "exec_argv", "queue_depth"]) ||
        !WORKER_STATES.some((state) => state === message.state) ||
        !isBoundedStringList(message.env_names, STATUS_LIST_MAX_ITEMS, STATUS_ITEM_MAX_LENGTH) ||
        !isBoundedStringList(message.exec_argv, STATUS_LIST_MAX_ITEMS, STATUS_ITEM_MAX_LENGTH) ||
        typeof message.queue_depth !== "number" ||
        !Number.isSafeInteger(message.queue_depth) ||
        message.queue_depth < 0
      ) {
        return null;
      }
      return {
        type: "status",
        state: message.state as WorkerState,
        env_names: [...message.env_names],
        exec_argv: [...message.exec_argv],
        queue_depth: message.queue_depth,
      };
    }
    default:
      return null;
  }
}

/** Serialized size as the advanced IPC channel carries it. */
export function ipcMessageBytes(message: unknown): number {
  return serialize(message).length;
}

/**
 * The one gate for both directions, on send and on receive: the shared schema
 * and the serialized size cap. Null for anything outside either. Must match
 * the receive handling in worker-client.ts and worker-entry.ts, which call
 * this rather than the parse functions directly.
 */
export function acceptMessage(direction: "to_worker", value: unknown): ParentMessage | null;
export function acceptMessage(direction: "to_parent", value: unknown): WorkerMessage | null;
export function acceptMessage(direction: "to_worker" | "to_parent", value: unknown): ParentMessage | WorkerMessage | null {
  const parsed = direction === "to_worker" ? parseParentMessage(value) : parseWorkerMessage(value);
  if (parsed === null) return null;
  let bytes: number;
  try {
    bytes = ipcMessageBytes(value);
  } catch {
    return null;
  }
  // The cap is measured on the serialized bytes, the same measure on both sides, so neither side accepts more than the other sends.
  return bytes <= IPC_MESSAGE_MAX_BYTES ? parsed : null;
}

/** Validate an outgoing message through acceptMessage; throws before anything is sent. */
export function assertSendable(direction: "to_worker" | "to_parent", message: unknown): void {
  const accepted = direction === "to_worker" ? acceptMessage(direction, message) : acceptMessage(direction, message);
  if (accepted === null) throw new WorkerProtocolError();
}
