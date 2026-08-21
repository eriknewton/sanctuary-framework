import { randomBytes } from "node:crypto";
import { createConnection } from "node:net";

import { CASTLE_WALL_RELOAD_CLIENT_TIMEOUT_MS } from "../constants.js";
import { frame, parseFrame } from "../ipc/framing.js";
import { POLICY_RELOAD_STAGES } from "../ipc/messages.js";
import type {
  CastleWallMessage,
  PolicyReloadStage,
  PolicyReloadResponse,
} from "../ipc/messages.js";
import { resolveCastleWallSocketPath } from "./socket-path.js";

/** Result of {@link requestPolicyReload}. */
export interface PolicyReloadResult {
  ok: boolean;
  loadedRuleCount?: number;
  error?: string;
  /** True when the failure was an unreachable daemon socket (no daemon running). */
  socketUnavailable?: boolean;
}

async function sendCastleWallMessage<T extends CastleWallMessage>(
  socketPath: string,
  message: CastleWallMessage,
  expectedType: T["type"],
  timeoutMs = 5_000,
): Promise<T> {
  return await new Promise<T>((resolvePromise, reject) => {
    const socket = createConnection(socketPath);
    let inbound = new Uint8Array(0);
    let settled = false;
    const timer = setTimeout(() => {
      finish(new Error("Castle Wall IPC request timed out"));
    }, timeoutMs);
    const finish = (result: T | Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (result instanceof Error) reject(result);
      else resolvePromise(result);
    };
    socket.on("connect", () => {
      socket.write(frame(JSON.stringify({
        jsonrpc: "2.0",
        method: `castle-wall.${message.type}`,
        params: message,
      })));
    });
    socket.on("data", (chunk: Buffer) => {
      const merged = new Uint8Array(inbound.length + chunk.length);
      merged.set(inbound, 0);
      merged.set(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.length), inbound.length);
      inbound = merged;
      while (inbound.length > 0) {
        const parsed = parseFrame(inbound);
        if (parsed.kind === "need_more") break;
        if (parsed.kind === "error") {
          finish(new Error(`Castle Wall IPC framing error: ${parsed.reason}`));
          return;
        }
        inbound = inbound.slice(parsed.consumedBytes);
        try {
          const envelope = JSON.parse(parsed.body) as { params?: CastleWallMessage };
          if (envelope.params?.type === expectedType) {
            finish(envelope.params as T);
            return;
          }
        } catch {
          // Ignore malformed frames from non-admin peers until timeout.
        }
      }
    });
    socket.on("error", finish);
  });
}

function isSocketUnavailable(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    ((error as NodeJS.ErrnoException).code === "ENOENT" ||
      (error as NodeJS.ErrnoException).code === "ECONNREFUSED")
  );
}

function isPolicyReloadStage(value: unknown): value is PolicyReloadStage {
  return typeof value === "string" &&
    (POLICY_RELOAD_STAGES as readonly string[]).includes(value);
}

function isBoundedElapsedMs(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function formatReloadFailure(reply: PolicyReloadResponse): string {
  const message = reply.error ?? "policy reload failed";
  if (
    !isPolicyReloadStage(reply.failure_stage) ||
    !isBoundedElapsedMs(reply.failure_stage_elapsed_ms) ||
    !isBoundedElapsedMs(reply.reload_elapsed_ms)
  ) {
    return message;
  }
  return `${message} [stage=${reply.failure_stage} stage_ms=${reply.failure_stage_elapsed_ms} total_ms=${reply.reload_elapsed_ms}]`;
}

/**
 * Ask the running Castle Wall policy daemon for this fortress to re-read,
 * re-compose, re-sign, and broadcast its manifest. FAIL-CLOSED result shape:
 * an unreachable socket is `ok: false` (with `socketUnavailable: true`),
 * never a silent success.
 */
export async function requestPolicyReload(
  fortressPath: string,
  platform: NodeJS.Platform = process.platform,
): Promise<PolicyReloadResult> {
  const socketPath = resolveCastleWallSocketPath({ platform, fortressPath }).path;
  try {
    // The daemon recomposes + re-signs from `policy/egress/rules/`, so no
    // `manifest_path` is sent. A reload re-signs through the root helper,
    // which is slower than a status query, so it gets its own client deadline.
    const reply = await sendCastleWallMessage<PolicyReloadResponse>(
      socketPath,
      {
        type: "policy_reload_request",
        request_id: randomBytes(16).toString("hex"),
      },
      "policy_reload_response",
      CASTLE_WALL_RELOAD_CLIENT_TIMEOUT_MS,
    );
    if (!reply.ok) {
      return { ok: false, error: formatReloadFailure(reply) };
    }
    return { ok: true, loadedRuleCount: reply.loaded_rule_count };
  } catch (error) {
    if (isSocketUnavailable(error)) {
      return {
        ok: false,
        socketUnavailable: true,
        error: `no Castle Wall daemon reachable at ${socketPath}`,
      };
    }
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}
