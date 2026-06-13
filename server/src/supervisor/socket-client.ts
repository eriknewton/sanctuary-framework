/**
 * Phase S1 — Supervisor local-socket client (dashboard side).
 *
 * The dashboard process (which owns the one-time fortress unlock + HTTP
 * surface) uses this to hand the supervisor a protect/unprotect/status request
 * over the authenticated `AF_UNIX` socket. It sends ONE MAC-authenticated,
 * length-bounded frame and reads ONE response, then closes. The transient key
 * travels only inside the protect frame and is dropped from the dashboard's
 * heap as soon as the frame is on the wire.
 */

import { connect, type Socket } from "node:net";
import {
  FrameDecoder,
  encodeFrame,
  type SupervisorRequest,
  type SupervisorResponse,
} from "./protocol.js";

export interface SocketClientOptions {
  socketPath: string;
  authSecret: Uint8Array;
  /** Per-request timeout (ms). Defaults to 10s. */
  timeoutMs?: number;
}

/**
 * Send one request and await one response over a fresh connection. Rejects on
 * connect failure, timeout, a MAC-failed/oversized response frame, or a
 * malformed response — the caller (dashboard) maps a rejection to a 503
 * `unavailable` (the supervisor subsystem is down/unreachable), never to a
 * silent success.
 */
export function sendSupervisorRequest(
  req: SupervisorRequest,
  opts: SocketClientOptions,
): Promise<SupervisorResponse> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  return new Promise<SupervisorResponse>((resolve, reject) => {
    const decoder = new FrameDecoder(opts.authSecret);
    let settled = false;
    const socket: Socket = connect(opts.socketPath);

    const done = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      fn();
    };

    socket.setTimeout(timeoutMs, () => done(() => reject(new Error("supervisor request timed out"))));
    socket.on("error", (err) => done(() => reject(err)));
    // If the supervisor drops the connection (e.g. a MAC-failed/over-budget
    // frame, or the wrong auth secret) it closes WITHOUT a response. Treat a
    // close before a settled response as a failure, never a silent success.
    socket.on("close", () => done(() => reject(new Error("supervisor closed the connection without a response"))));

    socket.on("connect", () => {
      try {
        socket.write(encodeFrame(opts.authSecret, req));
      } catch (err) {
        done(() => reject(err instanceof Error ? err : new Error(String(err))));
      }
    });

    socket.on("data", (chunk: Buffer) => {
      const outcome = decoder.push(chunk);
      if (outcome.status === "incomplete") return;
      if (outcome.status === "error") {
        done(() => reject(new Error(`supervisor response frame ${outcome.reason}`)));
        return;
      }
      const resp = outcome.message as SupervisorResponse;
      if (typeof resp !== "object" || resp === null || typeof (resp as { ok?: unknown }).ok !== "boolean") {
        done(() => reject(new Error("malformed supervisor response")));
        return;
      }
      done(() => resolve(resp));
    });
  });
}
