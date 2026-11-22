/**
 * The one IPC schema between the server and the local job worker, used by
 * both sides on send and on receive. Must match the message handling in
 * worker-client.ts and worker-entry.ts; 1b adds job messages here.
 *
 * No message carries record text, a result or a free-form error string, and
 * only `init` carries key bytes (the two derived store keys).
 */
import { serialize } from "node:v8";
import { isAbsolute } from "node:path";
import { CROSS_PROCESS_LOCK_TIMEOUT_MS } from "../storage/cross-process-lock.js";
import { KIB, LOCAL_STORE_KEY_BYTES, SECOND_MS } from "./store-record.js";

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

export type ParentMessage =
  | { type: "init"; storage_root: string; oplog_key: Uint8Array; results_key: Uint8Array }
  | { type: "shutdown" };

export type WorkerMessage =
  | { type: "ready" }
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
  return null;
}

/** Parse a worker-to-parent message; null for anything outside the schema. */
export function parseWorkerMessage(value: unknown): WorkerMessage | null {
  const message = record(value);
  if (message === null) return null;
  switch (message.type) {
    case "ready":
      return exactKeys(message, ["type"]) ? { type: "ready" } : null;
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

/** Validate an outgoing message against the shared schema and the size cap; throws before anything is sent. */
export function assertSendable(direction: "to_worker" | "to_parent", message: unknown): void {
  const parsed = direction === "to_worker" ? parseParentMessage(message) : parseWorkerMessage(message);
  // The cap is measured on the serialized bytes, so no message can grow the channel past it.
  if (parsed === null || ipcMessageBytes(message) > IPC_MESSAGE_MAX_BYTES) throw new WorkerProtocolError();
}
