/**
 * Phase S1 — Split-process supervisor: local-socket protocol.
 *
 * The supervised-daemon design (Supervised_Daemon_Decision_Brief_2026-06-13)
 * ratifies a SPLIT-PROCESS model (review finding H1): the dashboard process
 * owns the one-time fortress unlock and the browser-facing HTTP surface; a
 * SEPARATE small supervisor process owns spawning + supervising the wrapped
 * agent and holds only a TRANSIENT key. They speak over a local-only
 * `AF_UNIX` socket. This module defines that wire protocol so neither side
 * trusts the other implicitly:
 *
 *   - operator-uid-only: the socket lives in a 0700 directory OWNED by the
 *     operator uid (the supervisor verifies both the dir mode and its owner
 *     uid before binding — socket-server.ts), and the socket file is 0600.
 *     Node does not expose per-connection peer credentials (no SO_PEERCRED /
 *     LOCAL_PEERCRED binding), so the kernel's filesystem permission check IS
 *     the uid boundary: a process of a different uid cannot `connect()` to a
 *     0600 socket inside a 0700 operator-owned dir. This is the same mechanism
 *     the SSH agent socket relies on. A frame that nonetheless arrives without
 *     a valid MAC is dropped with NO response (no oracle), mirroring agents.ts.
 *   - authenticated: every frame carries an HMAC over the canonical request
 *     bytes keyed by a per-boot shared secret the dashboard hands the
 *     supervisor at spawn (env, never on disk). A frame whose MAC does not
 *     verify is dropped — the supervisor never acts on an unauthenticated
 *     request even from the right uid (defence in depth against a same-uid
 *     compromised process that found the socket path).
 *   - bounded: frames are length-prefixed and capped at {@link MAX_FRAME_BYTES};
 *     an over-long or malformed length prefix closes the connection. No
 *     unbounded buffering, no JSON parse before the length+MAC gate.
 *
 * The TRANSIENT KEY (the fortress master, or a per-agent derived capability)
 * is carried only inside the `protect` request's authenticated, length-bounded
 * frame, and only while the operator is launching an agent. It is never
 * written to disk and never touches the HTTP surface. Residency, stated
 * honestly (do NOT over-claim — codex S1): on a FAILED/refused/timed-out/
 * superseded/burst-parked launch the supervisor zeroes the key immediately;
 * on a SUCCESSFUL launch it RETAINS the key in memory for the agent's lifetime
 * (Tier A keeps it resident to restart the child on crash) and zeroes it on
 * unprotect/shutdown. See supervisor.ts for the exact zeroing points.
 *
 * This file is transport-shaping + crypto only; the supervisor lifecycle lives
 * in supervisor.ts and the Node socket plumbing in socket-server.ts /
 * socket-client.ts, so the protocol can be unit-tested without opening a real
 * socket.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { LOCAL_HARNESS_KINDS } from "../contracts/v1.1/local-agent-records.js";

/** Wire-protocol version. A mismatch is rejected (no silent downgrade). */
export const SUPERVISOR_PROTOCOL_VERSION = 1 as const;

/**
 * Hard cap on a single frame. Generous for a protect request (a harness kind,
 * a config path, an agent id, a base64url transient key, an HMAC) but small
 * enough that a malformed length prefix can never drive an allocation. A frame
 * claiming more than this closes the connection without buffering.
 */
export const MAX_FRAME_BYTES = 64 * 1024;

/** Length of the per-boot shared auth secret (bytes). */
export const SUPERVISOR_AUTH_SECRET_BYTES = 32;

/** Mint a fresh per-boot auth secret. Handed to the supervisor at spawn. */
export function mintAuthSecret(): Uint8Array {
  return randomBytes(SUPERVISOR_AUTH_SECRET_BYTES);
}

// ── Request / response shapes ───────────────────────────────────────────────

/** Supervisor request kinds the dashboard can issue. */
export type SupervisorRequest =
  | ProtectRequest
  | UnprotectRequest
  | StatusRequest;

export interface ProtectRequest {
  kind: "protect";
  /** Stable agent id this supervised spec is keyed by. */
  agent_id: string;
  /** Harness kind (validated against a known set on the supervisor side). */
  harness: string;
  /** Path to the harness config to rewrite/launch under; root-confined. */
  config_path: string;
  /**
   * The transient unlock key (base64url of the fortress master, or a derived
   * per-agent capability). Carried ONLY inside this authenticated frame;
   * never logged, never persisted. Residency (honest — codex S1): zeroed on a
   * failed/refused launch; RETAINED for the agent lifetime on a successful one
   * (Tier A crash-restart), then zeroed on unprotect/shutdown.
   */
  transient_key_b64: string;
}

export interface UnprotectRequest {
  kind: "unprotect";
  agent_id: string;
}

export interface StatusRequest {
  kind: "status";
  /** Omit to request every supervised agent's status. */
  agent_id?: string;
}

/** Supervisor response kinds. */
export type SupervisorResponse =
  | { ok: true; kind: "protecting"; agent_id: string; launch_id: string }
  | { ok: true; kind: "already-protected"; agent_id: string }
  | { ok: true; kind: "unprotecting"; agent_id: string }
  | { ok: true; kind: "status"; agents: SupervisedAgentStatus[] }
  | { ok: false; kind: "error"; reason: SupervisorErrorReason };

/**
 * Fail-closed error reasons. The dashboard maps these onto HTTP, collapsing
 * the security-sensitive ones into a generic 403 so the supervisor is no more
 * of an oracle than the HTTP surface (agents.ts no-oracle discipline).
 */
export type SupervisorErrorReason =
  | "bad_request" // malformed/over-long/MAC-failed frame, or unknown harness
  | "rotation_in_progress" // master rotation journal present — refuse to launch
  | "unavailable" // supervisor cannot service the request right now (retryable)
  | "not_found"; // unprotect/status for an unknown agent

/** Lifecycle state of a supervised agent, surfaced to the dashboard. */
export type SupervisedAgentState =
  | "protecting"
  | "protected" // enforcement-evidenced healthy (NOT pid-liveness alone)
  | "degraded" // process alive but no fresh enforcement evidence
  | "crashed" // exited; restart-backoff exhausted or parked
  | "needs-unlock" // supervisor restarted/rebooted; awaiting re-unlock (Tier A)
  | "stopping"
  | "stopped";

export interface SupervisedAgentStatus {
  agent_id: string;
  harness: string;
  state: SupervisedAgentState;
  /** Restart attempts since the last clean launch. */
  restarts: number;
  /** ISO8601 of the most recent enforcement evidence, or null if none yet. */
  last_enforcement_at: string | null;
}

// ── Frame encode / decode (length-prefixed, MAC-authenticated) ──────────────
//
// Wire layout (all integers big-endian):
//   [u32 payloadLen][32-byte HMAC-SHA256 over (version || payload)][payload]
// where `payload` is the UTF-8 JSON of the request/response object and
// `version` is a single byte. The MAC binds the version so a downgrade flips
// the MAC. payloadLen counts only the JSON bytes (not the version/MAC).

const VERSION_BYTE = Uint8Array.of(SUPERVISOR_PROTOCOL_VERSION);
const MAC_BYTES = 32;
const LEN_BYTES = 4;
/** Bytes of framing overhead ahead of the JSON payload. */
export const FRAME_HEADER_BYTES = LEN_BYTES + MAC_BYTES;

function computeMac(secret: Uint8Array, payload: Uint8Array): Uint8Array {
  const h = createHmac("sha256", Buffer.from(secret));
  h.update(VERSION_BYTE);
  h.update(payload);
  return h.digest();
}

/**
 * Encode a request/response object into an authenticated, length-prefixed
 * frame. Throws if the payload exceeds {@link MAX_FRAME_BYTES} so an
 * oversized object can never be put on the wire (the decoder rejects the same
 * bound defensively).
 */
export function encodeFrame(
  secret: Uint8Array,
  message: SupervisorRequest | SupervisorResponse,
): Uint8Array {
  const payload = Buffer.from(JSON.stringify(message), "utf-8");
  if (payload.length > MAX_FRAME_BYTES) {
    throw new RangeError("supervisor frame exceeds MAX_FRAME_BYTES");
  }
  const mac = computeMac(secret, payload);
  const out = Buffer.allocUnsafe(LEN_BYTES + MAC_BYTES + payload.length);
  out.writeUInt32BE(payload.length, 0);
  Buffer.from(mac).copy(out, LEN_BYTES);
  payload.copy(out, LEN_BYTES + MAC_BYTES);
  return out;
}

/** Result of feeding bytes to {@link FrameDecoder.push}. */
export type DecodeOutcome =
  | { status: "incomplete" } // need more bytes
  | { status: "frame"; message: unknown } // one verified frame decoded
  | { status: "error"; reason: "too_large" | "mac_failed" | "malformed" };

/**
 * Streaming frame decoder with a hard buffer bound and MAC verification.
 * Drops (returns "error") on:
 *   - a length prefix claiming more than MAX_FRAME_BYTES — rejected as soon as
 *     the 4-byte prefix is readable, so the decoder NEVER waits to buffer the
 *     claimed payload (no unbounded allocation driven by a hostile length);
 *   - an HMAC that does not verify (constant-time compare);
 *   - JSON that does not parse.
 *
 * Allocation honesty (do NOT over-claim — codex S1): `push` does concat the
 * raw incoming chunk onto its working buffer BEFORE reading the length prefix,
 * so allocation is bounded by what the transport hands it per chunk, not zero.
 * The hard bound is enforced by the caller: SupervisorSocketServer caps total
 * bytes per connection at PER_CONNECTION_READ_BUDGET (MAX_FRAME_BYTES + header)
 * and destroys the socket past it, so the decoder's working buffer can never
 * exceed ~one max frame. The two layers together give the bound; the prefix
 * check just rejects an over-claimed length before waiting for those bytes.
 * The caller closes the connection on any "error" — the protocol does not
 * attempt to resynchronise a corrupt stream.
 */
export class FrameDecoder {
  private buf: Buffer = Buffer.alloc(0);
  private readonly secret: Uint8Array;

  constructor(secret: Uint8Array) {
    this.secret = secret;
  }

  push(chunk: Uint8Array): DecodeOutcome {
    this.buf = Buffer.concat([this.buf, Buffer.from(chunk)]);

    if (this.buf.length < LEN_BYTES) return { status: "incomplete" };
    const payloadLen = this.buf.readUInt32BE(0);
    // Reject an over-long length BEFORE waiting to buffer that many bytes:
    // a malformed/hostile prefix can never drive unbounded allocation.
    if (payloadLen > MAX_FRAME_BYTES) {
      return { status: "error", reason: "too_large" };
    }

    const total = LEN_BYTES + MAC_BYTES + payloadLen;
    if (this.buf.length < total) return { status: "incomplete" };

    const mac = this.buf.subarray(LEN_BYTES, LEN_BYTES + MAC_BYTES);
    const payload = this.buf.subarray(LEN_BYTES + MAC_BYTES, total);
    const expected = computeMac(this.secret, payload);
    // Constant-time compare; lengths are fixed (32) so timingSafeEqual is safe.
    if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) {
      return { status: "error", reason: "mac_failed" };
    }

    // Consume the frame from the buffer before parsing so a parse failure
    // still advances the stream deterministically (caller will close anyway).
    this.buf = this.buf.subarray(total);

    let message: unknown;
    try {
      message = JSON.parse(payload.toString("utf-8"));
    } catch {
      return { status: "error", reason: "malformed" };
    }
    return { status: "frame", message };
  }

  /** Bytes currently buffered (test/diagnostic aid). */
  get buffered(): number {
    return this.buf.length;
  }
}

// ── Shape validation (post-MAC) ─────────────────────────────────────────────

/** Known harness kinds a supervised spec may name. Unknown ⇒ bad_request. */
export const SUPERVISOR_KNOWN_HARNESSES: ReadonlySet<string> = new Set(
  LOCAL_HARNESS_KINDS,
);

/**
 * Validate a decoded-and-MAC-verified object into a typed request. Returns
 * null on any shape violation (the supervisor maps null → bad_request). MAC
 * verification has already happened; this is structural only.
 */
export function parseRequest(message: unknown): SupervisorRequest | null {
  if (typeof message !== "object" || message === null) return null;
  const m = message as Record<string, unknown>;
  switch (m.kind) {
    case "protect": {
      if (typeof m.agent_id !== "string" || m.agent_id.length === 0) return null;
      if (typeof m.harness !== "string" || !SUPERVISOR_KNOWN_HARNESSES.has(m.harness)) {
        return null;
      }
      if (typeof m.config_path !== "string" || m.config_path.length === 0) return null;
      if (typeof m.transient_key_b64 !== "string" || m.transient_key_b64.length === 0) {
        return null;
      }
      return {
        kind: "protect",
        agent_id: m.agent_id,
        harness: m.harness,
        config_path: m.config_path,
        transient_key_b64: m.transient_key_b64,
      };
    }
    case "unprotect": {
      if (typeof m.agent_id !== "string" || m.agent_id.length === 0) return null;
      return { kind: "unprotect", agent_id: m.agent_id };
    }
    case "status": {
      if (m.agent_id !== undefined && typeof m.agent_id !== "string") return null;
      return { kind: "status", agent_id: m.agent_id as string | undefined };
    }
    default:
      return null;
  }
}
