/**
 * The `sanctuary_local_task` MCP tool. It accepts a summary task over stored
 * records, records one fixed submission row in the shared audit log, hands the
 * parsed request to the local job worker, and answers with one of four fixed
 * responses. Nothing about the job, its records or its result reaches the
 * agent: the result appears only on the operator surface.
 */
import { randomBytes } from "node:crypto";
import { isReservedNamespace } from "../cognitive/state-store.js";
import type { AuditEntryInput } from "../operational/audit-log.js";
import type { ToolDefinition } from "../router.js";
import { encodeFilesystemStorageName, filesystemStorageNameRoundTrips } from "../storage/filesystem-name-codec.js";
import { isStorageNamespacePathComponent } from "../storage/namespace-component.js";
import { INSTRUCTION_MAX_CHARS, SOURCE_REFS_MAX } from "./limits.js";
import type { JobDropCause } from "./oplog.js";
import { SeatRateTable } from "./rate.js";
import {
  LOCAL_TASK_DESCRIPTION,
  LOCAL_TASK_TOOL_NAME,
  busyResponse,
  invalidInputResponse,
  submittedResponse,
  unavailableResponse,
  type LocalTaskResponse,
} from "./responses.js";
import { STORAGE_NAME_MAX_CHARS, type LocalTaskJob, type LocalTaskRef } from "./worker-protocol.js";

/** The shared-log operation of an accepted submission; must match the reorg-surface manifest row. */
export const LOCAL_REQUEST_SUBMITTED_OPERATION = "local_request_submitted";

/** Request ids are 16 random bytes, 32 lowercase hex digits; must match isRequestId in store-record.ts. */
const REQUEST_ID_BYTES = 16;

/** Named handler states, in order. */
export const LOCAL_TASK_HANDLER_STATES = [
  "state_PARSE",
  "state_ARMED",
  "state_RATE",
  "state_ROW",
  "state_ENQUEUE",
  "state_ACK",
] as const;
export type LocalTaskHandlerState = (typeof LOCAL_TASK_HANDLER_STATES)[number];

/** Why the tool is disarmed; operator-side only, never in a response. Must match /api/local/status. */
export const LOCAL_TASK_DISARM_CAUSES = [
  "storage_injected",
  "test_runtime",
  "lock_root_unavailable",
  "stores_unavailable",
  "worker_unavailable",
] as const;
export type LocalTaskDisarmCause = (typeof LOCAL_TASK_DISARM_CAUSES)[number];

/** Everything an armed tool needs; every member is required, so no property is silently off. */
export interface ArmedLocalTask {
  /** Hands the job to the worker and watches it to a terminal state; must match LocalWorkerClient.submit. */
  workerClient: { submit(message: LocalTaskJob): "sent" | "queue_full" | "unavailable" };
  auditLog: { appendCritical(entry: AuditEntryInput): Promise<void> };
  authority: { register(job: { request_id: string; refs: readonly LocalTaskRef[] }): void; forget(requestId: string): void };
  /** The server's own operator-log writer, used only for drops it observes itself. */
  dropLog: { append(kind: "job_dropped", body: { request_id: string; cause: JobDropCause }): Promise<unknown> };
  clock: () => number;
  idSource: () => string;
  /** The seat a call counts against: the router's caller identity. */
  seat: (callerIdentity: string | undefined) => string;
}

export type LocalTaskArming =
  | { armed: true; bundle: ArmedLocalTask }
  | { armed: false; cause: LocalTaskDisarmCause };

export interface LocalTaskToolOptions {
  /** Test-only: runs at entry to each handler state; index.ts passes it only under Vitest. */
  callHook?: (state: LocalTaskHandlerState) => void;
}

export function defaultRequestId(): string {
  return randomBytes(REQUEST_ID_BYTES).toString("hex");
}

/** The router's caller identity is the seat; a call without one counts against the unbound seat. */
export function routerSeat(callerIdentity: string | undefined): string {
  return callerIdentity ?? "agent:unknown";
}

export const LOCAL_TASK_INPUT_SCHEMA = {
  type: "object",
  properties: {
    kind: { type: "string", enum: ["summarize"], description: "The task kind. Only summarize is available." },
    sources: {
      type: "object",
      description: `The records to summarize, as { "refs": [{ "namespace": "...", "key": "..." }] }, 1 to ${SOURCE_REFS_MAX} refs.`,
    },
    instruction: {
      type: "string",
      description: `What the summary should focus on, at most ${INSTRUCTION_MAX_CHARS} characters.`,
    },
  },
  required: ["kind", "sources", "instruction"],
} as const;

function plainObject(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  return value as Record<string, unknown>;
}

/** Exactly these own keys, and nothing inherited that enumerates. */
function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  if (own.length !== keys.length || !own.every((key) => keys.includes(key))) return false;
  let enumerated = 0;
  for (const key in value) {
    if (!Object.hasOwn(value, key)) return false;
    enumerated += 1;
  }
  return enumerated === keys.length;
}

function validStorageKey(key: string): boolean {
  if (key.includes("\0") || !filesystemStorageNameRoundTrips(key)) return false;
  const encoded = encodeFilesystemStorageName(key);
  return encoded !== "." && encoded !== ".." && encoded.length <= STORAGE_NAME_MAX_CHARS;
}

function validNamespace(namespace: string): boolean {
  return (
    !isReservedNamespace(namespace) &&
    isStorageNamespacePathComponent(namespace) &&
    encodeFilesystemStorageName(namespace).length <= STORAGE_NAME_MAX_CHARS
  );
}

// C0 controls, DEL and C1 controls, except tab and newline.
// eslint-disable-next-line no-control-regex
const FORBIDDEN_CONTROL = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/u;

/**
 * The handler's strict check, after the router's schema check. Null for any
 * input outside the grammar. Duplicate JSON keys are resolved by the SDK
 * parser before this runs; DEBT(LOCAL-TASK-DUPLICATE-KEYS).
 */
export function parseLocalTaskArgs(args: Record<string, unknown>): { refs: LocalTaskRef[]; instruction: string } | null {
  const top = plainObject(args);
  if (top === null || !hasExactKeys(top, ["kind", "sources", "instruction"]) || top.kind !== "summarize") return null;
  const sources = plainObject(top.sources);
  if (sources === null || !hasExactKeys(sources, ["refs"])) return null;
  const refs = sources.refs;
  if (!Array.isArray(refs) || refs.length < 1 || refs.length > SOURCE_REFS_MAX) return null;
  if (Object.getPrototypeOf(refs) !== Array.prototype || !hasExactKeys(refs as unknown as Record<string, unknown>, refs.map((_, i) => String(i)))) {
    return null;
  }
  const parsed: LocalTaskRef[] = [];
  for (const item of refs) {
    const ref = plainObject(item);
    if (ref === null || !hasExactKeys(ref, ["namespace", "key"])) return null;
    const { namespace, key } = ref;
    if (typeof namespace !== "string" || typeof key !== "string" || namespace.length === 0 || key.length === 0) return null;
    if (!validNamespace(namespace) || !validStorageKey(key)) return null;
    parsed.push({ namespace, key });
  }
  const instruction = top.instruction;
  if (typeof instruction !== "string") return null;
  if (Array.from(instruction).length > INSTRUCTION_MAX_CHARS || FORBIDDEN_CONTROL.test(instruction)) return null;
  return { refs: parsed, instruction };
}

/** Build the tool from its arming: an armed bundle or an explicit disarm cause. There is no in-process fallback. */
export function createLocalTaskTool(arming: LocalTaskArming, options: LocalTaskToolOptions = {}): ToolDefinition {
  const rate = new SeatRateTable();
  const hook = options.callHook ?? (() => undefined);

  const handler = async (args: Record<string, unknown>, callerIdentity?: string): Promise<LocalTaskResponse> => {
    let requestId: string | undefined;
    let rowSettled = false;
    let sent = false;
    let dropCause: JobDropCause = "worker_unavailable";
    let bundle: ArmedLocalTask | undefined;
    // Every throw from here on is answered with a fixed response, so the router never records a
    // tool_error for this tool: A1 once the submission row is durable, A3 before it.
    try {
      hook("state_PARSE");
      const parsed = parseLocalTaskArgs(args);
      if (parsed === null) return invalidInputResponse();

      hook("state_ARMED");
      if (!arming.armed) return unavailableResponse();
      bundle = arming.bundle;

      hook("state_RATE");
      const seat = bundle.seat(callerIdentity);
      if (!rate.admit(seat, bundle.clock())) return busyResponse();

      hook("state_ROW");
      requestId = bundle.idSource();
      // The submission row is durable before the acknowledgement; its details are only the fixed-length
      // id, so its stored size depends on the tool and the seat, never on the request or its job.
      await bundle.auditLog.appendCritical({
        layer: "l2",
        operation: LOCAL_REQUEST_SUBMITTED_OPERATION,
        identity_id: seat,
        result: "success",
        details: { request_id: requestId },
      });
      rowSettled = true;

      hook("state_ENQUEUE");
      bundle.authority.register({ request_id: requestId, refs: parsed.refs });
      // Never awaited: a worker that is dead or backlogged refuses at once, and the caller is answered the same.
      const outcome = bundle.workerClient.submit({
        type: "job",
        request_id: requestId,
        seat,
        kind: "summarize",
        refs: parsed.refs,
        instruction: parsed.instruction,
      });
      sent = outcome === "sent";
      if (outcome === "queue_full") dropCause = "queue_full";

      hook("state_ACK");
      return submittedResponse(requestId);
    } catch {
      return rowSettled && requestId !== undefined ? submittedResponse(requestId) : unavailableResponse();
    } finally {
      if (rowSettled && !sent && bundle !== undefined && requestId !== undefined) scheduleDrop(bundle, requestId, dropCause);
    }
  };

  return {
    name: LOCAL_TASK_TOOL_NAME,
    description: LOCAL_TASK_DESCRIPTION,
    tool_class: "write",
    inputSchema: LOCAL_TASK_INPUT_SCHEMA as unknown as Record<string, unknown>,
    handler,
  };
}

/**
 * An accepted call whose job never reached the worker is an operator-side drop.
 * The append is scheduled for after the response has gone, never before it, so
 * the agent's call takes the same time whether or not the worker took the job.
 */
function scheduleDrop(bundle: ArmedLocalTask, requestId: string, cause: JobDropCause): void {
  bundle.authority.forget(requestId);
  setImmediate(() => {
    bundle.dropLog.append("job_dropped", { request_id: requestId, cause }).catch(() => undefined);
  });
}
