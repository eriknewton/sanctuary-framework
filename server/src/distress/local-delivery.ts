/**
 * HABEAS PORT — emitter-side local delivery client.
 *
 * The in-process `sanctuary_distress` tool calls this AFTER its critical audit
 * append, best-effort, to hand the envelope to a local listener bound on
 * 127.0.0.1:8741 (the operator's standalone dashboard process). It is the
 * symmetric counterpart of listener.ts.
 *
 * Properties that keep this safe and non-disruptive:
 *
 *   - Best-effort, never blocking the lane. A short connect+write timeout; any
 *     failure (no listener, refused, timeout, nack) resolves to a failure
 *     result the caller audits like the webhook lane. The local stderr
 *     notification and the audit entry have ALREADY happened before this runs,
 *     so a delivery failure is never a new failure mode for emission.
 *
 *   - Authenticated. The frame carries an HMAC-SHA256 over the canonical
 *     envelope bytes with the operator-uid-only local secret, so the listener
 *     can reject spoofed frames from other local processes. The emitter holds
 *     the secret because it runs as the operator (same fortress dir).
 *
 *   - Bounded. One frame, written once, then half-close. A hard overall
 *     deadline. No retries (a retry storm would itself be a local DoS vector).
 */

import { connect } from "node:net";
import { randomBytes, timingSafeEqual } from "node:crypto";

import {
  HABEAS_DISTRESS_PORT,
  HABEAS_LOOPBACK_IPS,
} from "../castle-wall/allowlist/habeas-port.js";
import type { DistressEnvelope } from "./tools.js";
import {
  computeFrameHmac,
  computeChallengeProof,
  type DistressChallenge,
  type DistressClientHello,
  type DistressDeliveryFrame,
} from "./listener.js";

/** Client-nonce size (bytes). Fresh per delivery to defeat challenge harvest. */
const CLIENT_NONCE_BYTES = 24;

function proofEquals(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  try {
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

/** Overall deliver deadline (connect + write + ack). Short: the local lane is
 * loopback; anything slower than this is effectively "no listener". */
export const DISTRESS_DELIVER_TIMEOUT_MS = 1_500;

/** Max bytes we will read back as an ack before giving up (the listener replies
 * with a tiny status object). */
const ACK_MAX_BYTES = 1024;

export interface LocalDeliveryResult {
  delivered: boolean;
  reason?: string;
}

export interface LocalDeliveryOptions {
  envelope: DistressEnvelope;
  envelopeHash: string;
  /** Operator-uid-only shared secret (raw bytes). */
  localSecret: Uint8Array;
  host?: string;
  port?: number;
  timeoutMs?: number;
}

/**
 * Deliver one distress envelope to the local listener. Resolves (never
 * rejects) with `{ delivered }`. A false result is the caller's signal to
 * audit a best-effort failure — it is never fatal to the emission.
 */
export function deliverDistressLocally(
  options: LocalDeliveryOptions,
): Promise<LocalDeliveryResult> {
  const host = options.host ?? HABEAS_LOOPBACK_IPS[0];
  const port = options.port ?? HABEAS_DISTRESS_PORT;
  const timeoutMs = options.timeoutMs ?? DISTRESS_DELIVER_TIMEOUT_MS;

  // Fresh per-delivery client nonce. The listener's proof must bind THIS
  // nonce, so a pre-harvested {server_nonce, proof} pair cannot be replayed to
  // us by a port-squatter (codex round-2 HIGH).
  const clientNonce = randomBytes(CLIENT_NONCE_BYTES).toString("hex");
  const hello: DistressClientHello = {
    protocol: "sanctuary.distress.local.v1",
    client_nonce: clientNonce,
  };

  return new Promise<LocalDeliveryResult>((resolve) => {
    let settled = false;
    let frameSent = false;
    let challengeSeen = false;
    let buf = "";
    let totalBytes = 0;

    const finish = (result: LocalDeliveryResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };

    const socket = connect({ host, port });

    const timer = setTimeout(() => {
      finish({ delivered: false, reason: "timeout" });
    }, timeoutMs);

    socket.on("connect", () => {
      // Speak first: send our hello so the listener can bind our client nonce.
      socket.write(`${JSON.stringify(hello)}\n`);
    });

    socket.on("data", (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > ACK_MAX_BYTES) {
        finish({ delivered: false, reason: "peer_overrun" });
        return;
      }
      buf += chunk.toString("utf8");

      if (!challengeSeen) {
        // Awaiting the listener's challenge (one newline-terminated line).
        const nl = buf.indexOf("\n");
        if (nl === -1) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        challengeSeen = true;
        let challenge: DistressChallenge;
        try {
          challenge = JSON.parse(line) as DistressChallenge;
        } catch {
          finish({ delivered: false, reason: "bad_challenge" });
          return;
        }
        // Verify the listener's proof binds OUR fresh client nonce (so it
        // cannot be a replayed pre-harvested challenge) AND its own server
        // nonce. A port-squatter without the secret cannot produce this proof,
        // so it never receives the distress content.
        if (
          challenge.protocol !== "sanctuary.distress.local.v1" ||
          typeof challenge.nonce !== "string" ||
          !proofEquals(
            challenge.proof,
            computeChallengeProof(clientNonce, challenge.nonce, options.localSecret),
          )
        ) {
          finish({ delivered: false, reason: "listener_unauthenticated" });
          return;
        }
        // Authenticated, live listener: send the server-nonce-bound frame and
        // half-close.
        const frame: DistressDeliveryFrame = {
          envelope: options.envelope,
          envelope_hash: options.envelopeHash,
          hmac: computeFrameHmac(options.envelope, challenge.nonce, options.localSecret),
        };
        frameSent = true;
        socket.end(JSON.stringify(frame));
        return;
      }
      // After the frame, buf accumulates the ack until 'end'.
    });

    socket.on("end", () => {
      if (!frameSent) {
        finish({ delivered: false, reason: "no_challenge" });
        return;
      }
      try {
        const ack = JSON.parse(buf) as { ok?: boolean; reason?: string };
        if (ack.ok === true) {
          finish({ delivered: true });
        } else {
          finish({ delivered: false, reason: ack.reason ?? "nack" });
        }
      } catch {
        finish({ delivered: false, reason: "bad_ack" });
      }
    });

    // No listener bound / refused / reset: best-effort failure, never thrown.
    socket.on("error", (err: NodeJS.ErrnoException) => {
      finish({ delivered: false, reason: err.code ?? "error" });
    });
  });
}
