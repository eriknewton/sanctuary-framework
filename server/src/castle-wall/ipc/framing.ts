/**
 * LSP-style framing for Castle Wall IPC.
 *
 * Each frame is `Content-Length: <n>\r\n\r\n<n bytes UTF-8 JSON>`. This module
 * is the pure framing logic; transport layers (Linux UDS, macOS XPC adapter)
 * use it to read and write frames. PR 2 wires the Linux UDS transport and
 * SO_PEERCRED auth on top.
 *
 * Source: Castle Wall Phase 1 Scope Lock 2026-05-03 section 5.
 */

import { CASTLE_WALL_IPC_CONTENT_LENGTH_HEADER } from "../constants.js";
import { IpcFramingError } from "../errors.js";
// header bytes arrive off the IPC socket, so the decoded text is unbounded
// attacker input and goes through the untrusted-diagnostic chokepoint (STATE-
// STORE-ERRMSG-INTERP-01).
import { describeUntrusted } from "../../errors/index.js";

const DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024; // 16 MB
const MIN_MAX_FRAME_BYTES = 1024;
const MAX_MAX_FRAME_BYTES = 1024 * 1024 * 1024; // 1 GB

function loadMaxFrameBytes(): number {
  const env = process.env.SANCTUARY_MAX_FRAME_BYTES;
  if (env == null || env === "") return DEFAULT_MAX_FRAME_BYTES;
  const parsed = Number(env);
  if (!Number.isInteger(parsed) || parsed < MIN_MAX_FRAME_BYTES || parsed > MAX_MAX_FRAME_BYTES) {
    throw new Error(
      `SANCTUARY_MAX_FRAME_BYTES must be an integer between ${MIN_MAX_FRAME_BYTES} and ${MAX_MAX_FRAME_BYTES}, got: ${env}`
    );
  }
  return parsed;
}

export const MAX_FRAME_BYTES = loadMaxFrameBytes();

const HEADER_END = "\r\n\r\n";
const HEADER_END_BYTES = new TextEncoder().encode(HEADER_END);

/** Encode an already-serialized JSON body into an LSP-framed buffer. */
export function frame(jsonBody: string): Uint8Array {
  const bodyBytes = new TextEncoder().encode(jsonBody);
  const header = `${CASTLE_WALL_IPC_CONTENT_LENGTH_HEADER}: ${bodyBytes.length}\r\n\r\n`;
  const headerBytes = new TextEncoder().encode(header);
  const out = new Uint8Array(headerBytes.length + bodyBytes.length);
  out.set(headerBytes, 0);
  out.set(bodyBytes, headerBytes.length);
  return out;
}

/**
 * Result of a parse step. The caller feeds the framing parser bytes from the
 * transport; the parser returns either a fully decoded body, or "need more
 * bytes," or a hard error. Hard errors close the connection per scope-lock.
 */
export type ParseStep =
  | { kind: "complete"; body: string; consumedBytes: number }
  | { kind: "need_more" }
  | {
      kind: "error";
      reason: string;
      /**
       * Set when the error is specifically an oversize-frame rejection. Lets
       * callers distinguish the resource-bound rejection from other framing
       * errors without inspecting the reason string. Audit emission for this
       * surface is intentionally not done here; the IPC layer is a privileged
       * daemon -> userspace channel and audit events flow through the Castle
       * Wall typed event surface (see castle-wall/audit/events.ts) in a
       * separate scope.
       */
      oversize?: { declaredLength: number; maxAllowed: number };
    };

/** Find the byte offset of the header terminator within `buf`, or -1. */
function findHeaderEnd(buf: Uint8Array): number {
  outer: for (let i = 0; i + HEADER_END_BYTES.length <= buf.length; i++) {
    for (let j = 0; j < HEADER_END_BYTES.length; j++) {
      if (buf[i + j] !== HEADER_END_BYTES[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * Parse one frame from `buf`. Caller is responsible for accumulating bytes
 * across reads and slicing out `consumedBytes` after a "complete" result.
 *
 * Throws IpcFramingError only for non-recoverable transport-level mistakes
 * (negative length, malformed header). For partial frames, returns "need_more".
 */
export function parseFrame(buf: Uint8Array): ParseStep {
  const headerEnd = findHeaderEnd(buf);
  if (headerEnd === -1) {
    return { kind: "need_more" };
  }

  const headerText = new TextDecoder("utf-8").decode(buf.subarray(0, headerEnd));
  const lines = headerText.split("\r\n").filter((line) => line.length > 0);
  let contentLength: number | null = null;
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon === -1) {
      return { kind: "error", reason: `malformed header line: ${describeUntrusted(line)}` };
    }
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    if (name.toLowerCase() === CASTLE_WALL_IPC_CONTENT_LENGTH_HEADER.toLowerCase()) {
      const parsed = Number(value);
      if (!Number.isInteger(parsed) || parsed < 0) {
        return { kind: "error", reason: `invalid Content-Length value: ${describeUntrusted(value)}` };
      }
      contentLength = parsed;
    }
  }
  if (contentLength === null) {
    return { kind: "error", reason: "missing Content-Length header" };
  }

  if (contentLength > MAX_FRAME_BYTES) {
    return {
      kind: "error",
      reason: `frame exceeds max bytes: ${contentLength} > ${MAX_FRAME_BYTES}`,
      oversize: { declaredLength: contentLength, maxAllowed: MAX_FRAME_BYTES },
    };
  }

  const bodyStart = headerEnd + HEADER_END_BYTES.length;
  const totalNeeded = bodyStart + contentLength;
  if (buf.length < totalNeeded) {
    return { kind: "need_more" };
  }
  const body = new TextDecoder("utf-8").decode(buf.subarray(bodyStart, totalNeeded));
  return { kind: "complete", body, consumedBytes: totalNeeded };
}

/**
 * Helper for unit tests and tooling: synchronously parse one frame from
 * complete bytes. Throws if not exactly one frame is present.
 */
export function parseSingleFrame(buf: Uint8Array): string {
  const step = parseFrame(buf);
  if (step.kind === "error") {
    throw new IpcFramingError(step.reason);
  }
  if (step.kind === "need_more") {
    throw new IpcFramingError("incomplete frame");
  }
  if (step.consumedBytes !== buf.length) {
    throw new IpcFramingError(
      `extra bytes after frame: consumed ${step.consumedBytes} of ${buf.length}`
    );
  }
  return step.body;
}
