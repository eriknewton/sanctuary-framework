/**
 * HABEAS PORT — local distress listener (binds 127.0.0.1:8741).
 *
 * The network surface of the local distress lane. It runs in the long-lived
 * operator process (the standalone dashboard) and receives distress
 * deliveries from the in-process emitter (the MCP server's `sanctuary_distress`
 * tool), then persists them to the operator-readable inbox so the dashboard
 * can surface them.
 *
 * SECURITY MODEL (codex will attack this):
 *
 *   1. Sender authentication. ANY local process can connect to
 *      127.0.0.1:8741 — including the wrapped agent's own process tree. So
 *      loopback is NOT trust. Every frame must carry a valid HMAC-SHA256 over
 *      the canonical envelope bytes, keyed with the operator-uid-only local
 *      secret (see local-secret.ts). A frame whose signature does not verify
 *      is rejected with no inbox write and an audited rejection. The secret is
 *      a 0600 file the agent's MCP surface cannot read.
 *
 *   2. No information leak. The listener NEVER serves distress content back to
 *      a connecting peer. A delivery connection is write-only from the peer's
 *      side: the listener reads one frame, replies with a tiny ack/nack status
 *      (no envelope echo), and closes. Reading the inbox is the dashboard's
 *      job, behind the dashboard's existing auth.
 *
 *   3. Bounded. Closed envelope shape (same validator the lane already uses),
 *      hard frame-size cap, per-connection read timeout, and a concurrent
 *      connection cap. A peer that opens the socket and stalls is dropped on
 *      timeout, so it cannot hold the port. A peer that floods bytes is cut at
 *      the size cap. These make the listener un-DoS-able by a local peer
 *      holding connections open.
 *
 *   4. Additive, never a new failure mode. The listener is OPTIONAL. If it is
 *      not running (no operator dashboard process), emission is unchanged:
 *      stderr notification + audit, exactly as shipped. The emitter delivers
 *      to the listener AFTER its audit append, best-effort; a delivery failure
 *      (port closed, connection refused, nack) is audited like the webhook
 *      lane and never affects the local notification or the audit entry.
 *
 *   5. Port conflict is loud, never a crash loop. If bind fails (EADDRINUSE or
 *      otherwise) the listener logs a clear warning to stderr and resolves
 *      without throwing. The dashboard keeps running; only the local network
 *      leg of the distress lane is unavailable, and that is the documented
 *      degraded mode (in-process stderr + audit still hold).
 */

import { createServer, type Server, type Socket } from "node:net";

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  HABEAS_DISTRESS_PORT,
  HABEAS_LOOPBACK_IPS,
} from "../castle-wall/allowlist/habeas-port.js";
import { canonicalJson, sha256 } from "../agent-native/safety-base.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import type { DistressInbox } from "./inbox.js";
import {
  DISTRESS_REASONS,
  DISTRESS_SEVERITIES,
  type DistressEnvelope,
  type DistressReason,
  type DistressSeverity,
} from "./tools.js";

/** Max bytes accepted for a single delivery frame. The frame is one JSON
 * object: envelope + hash + hex HMAC. The envelope itself is hard-bounded
 * (closed enums + 280-char detail), so a few KB is generous; anything larger
 * is a malformed/hostile peer. */
export const DISTRESS_FRAME_MAX_BYTES = 8 * 1024;

/** Per-connection read deadline. A peer that does not deliver a complete frame
 * in this window is dropped so it cannot hold the socket open. */
export const DISTRESS_CONN_TIMEOUT_MS = 2_000;

/** Max concurrent in-flight connections. Beyond this, new connections are
 * immediately destroyed — a local peer cannot exhaust the listener by opening
 * many idle sockets. */
export const DISTRESS_MAX_CONNECTIONS = 16;

/** The emitter's opening hello: a fresh client nonce the listener must bind
 * into its proof (anti-harvest freshness). */
export interface DistressClientHello {
  protocol: "sanctuary.distress.local.v1";
  client_nonce: string;
}

/** The challenge the listener sends in response, proving it holds the secret
 * AND that its proof is fresh for this emitter's client nonce. */
export interface DistressChallenge {
  protocol: "sanctuary.distress.local.v1";
  /** Per-connection random server nonce the frame HMAC must bind. */
  nonce: string;
  /** HMAC over (client_nonce || server_nonce), proving the listener holds the
   * secret and cannot be a replayed pre-harvested challenge. */
  proof: string;
}

/** The wire frame the emitter sends after verifying the challenge. */
export interface DistressDeliveryFrame {
  envelope: DistressEnvelope;
  envelope_hash: string;
  /** Hex HMAC-SHA256 over (domain || nonce || canonicalJson(envelope)) with
   * the local secret. Nonce-bound, so it is not replayable. */
  hmac: string;
}

/** Bound on retained accepted event_ids for cross-connection replay defense. */
export const DISTRESS_SEEN_EVENTS_MAX = 1024;

/** Nonce size in bytes. */
const NONCE_BYTES = 24;

export interface DistressListenerOptions {
  inbox: DistressInbox;
  auditLog: AuditLog;
  /** Operator-uid-only shared secret (raw bytes). */
  localSecret: Uint8Array;
  /** Fortress/operator id for audit attribution. */
  identityId: string;
  /** Injectable clock for tests. */
  now?: () => number;
  /** Injectable warning sink (defaults to stderr). */
  warn?: (line: string) => void;
  /** Bind host override (tests use an ephemeral loopback). Production binds the
   * fixed loopback literal. */
  host?: string;
  /** Bind port override (tests use 0 for an ephemeral port). */
  port?: number;
}

/** Result of a verify+store attempt, for audit + test assertions. */
export type DeliveryRejection =
  | "too_large"
  | "malformed"
  | "bad_envelope"
  | "bad_signature"
  | "replay"
  | "store_failed";
export type DeliveryOutcome =
  | { ok: true; event_id: string }
  | { ok: false; reason: DeliveryRejection };

/**
 * Compute the canonical HMAC the emitter and listener both use. The signature
 * is bound to a per-connection server nonce so that (a) it is not replayable —
 * a captured frame is valid only for the one connection whose nonce it carries
 * — and (b) the emitter can demand the listener prove possession of the secret
 * BEFORE sending the envelope (mutual auth, anti port-squat). The nonce and the
 * canonical envelope are domain-separated so neither can be confused for the
 * other.
 */
export function computeFrameHmac(
  envelope: DistressEnvelope,
  nonce: string,
  secret: Uint8Array,
): string {
  return createHmac("sha256", secret)
    .update("sanctuary.distress.frame.v1\n")
    .update(`${nonce}\n`)
    .update(canonicalJson(envelope))
    .digest("hex");
}

/**
 * The listener's proof that IT holds the secret, bound to BOTH the emitter's
 * fresh client nonce and the listener's own server nonce. Binding the client
 * nonce is what makes the proof non-replayable: a port-squatter cannot harvest
 * a `{server_nonce, proof}` pair from the real listener and replay it to the
 * emitter, because the emitter demands a proof over the fresh client nonce IT
 * just generated (codex round-2 HIGH). Domain-separated from the frame HMAC so
 * a challenge proof can never be replayed as a frame signature or vice versa.
 */
export function computeChallengeProof(
  clientNonce: string,
  serverNonce: string,
  secret: Uint8Array,
): string {
  return createHmac("sha256", secret)
    .update("sanctuary.distress.challenge.v1\n")
    .update(`${clientNonce}\n`)
    .update(serverNonce)
    .digest("hex");
}

function hmacEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

/** Validate that a parsed value is a closed, in-bounds distress envelope.
 * Mirrors the emission-side closed shape: the listener does NOT trust the peer
 * to have sent a well-formed envelope just because the HMAC could verify (the
 * checks are ordered so structure is validated before any inbox write). */
const ENVELOPE_ALLOWED_KEYS = new Set<string>([
  "schema",
  "event_id",
  "emitted_at",
  "actor",
  "reason",
  "severity",
  "detail",
  "sequence_in_window",
]);

function isValidEnvelope(value: unknown): value is DistressEnvelope {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const e = value as Record<string, unknown>;
  // CLOSED shape: reject any extra key. A valid HMAC must not be a license to
  // smuggle arbitrary attacker-chosen fields into the encrypted inbox /
  // dashboard surface (codex round-1 MEDIUM: open-envelope false negative).
  for (const key of Object.keys(e)) {
    if (!ENVELOPE_ALLOWED_KEYS.has(key)) return false;
  }
  if (e.schema !== "sanctuary.distress.v1") return false;
  if (typeof e.event_id !== "string" || e.event_id.length === 0) return false;
  if (typeof e.emitted_at !== "string" || e.emitted_at.length === 0) return false;
  if (typeof e.actor !== "string" || e.actor.length === 0) return false;
  if (!DISTRESS_REASONS.includes(e.reason as DistressReason)) return false;
  if (!DISTRESS_SEVERITIES.includes(e.severity as DistressSeverity)) return false;
  if (e.detail !== undefined && typeof e.detail !== "string") return false;
  if (typeof e.detail === "string" && e.detail.length > 280) return false;
  if (typeof e.sequence_in_window !== "number" || !Number.isFinite(e.sequence_in_window))
    return false;
  return true;
}

export class DistressListener {
  private server: Server | null = null;
  private readonly inbox: DistressInbox;
  private readonly auditLog: AuditLog;
  private readonly localSecret: Uint8Array;
  private readonly identityId: string;
  private readonly now: () => number;
  private readonly warn: (line: string) => void;
  private readonly host: string;
  private readonly port: number;
  private activeConnections = 0;
  /** Per-connection nonces issued and not yet consumed (anti-replay: a frame
   * is valid only against the live nonce of its own connection). */
  private readonly liveNonces = new Set<string>();
  /** Recently accepted event_ids (anti-replay across connections; bounded). */
  private readonly seenEventIds = new Set<string>();

  constructor(options: DistressListenerOptions) {
    this.inbox = options.inbox;
    this.auditLog = options.auditLog;
    this.localSecret = options.localSecret;
    this.identityId = options.identityId;
    this.now = options.now ?? (() => Date.now());
    this.warn =
      options.warn ??
      ((line: string) => {
        // SAFETY: stderr is the operator-facing console for the dashboard
        // service; no logger module is in scope here.
        console.error(line);
      });
    this.host = options.host ?? HABEAS_LOOPBACK_IPS[0];
    this.port = options.port ?? HABEAS_DISTRESS_PORT;
  }

  /**
   * Bind and start listening. A bind failure (port conflict) is loud but
   * non-fatal: it logs a warning and resolves, so the dashboard keeps running
   * with the in-process distress lane (stderr + audit) intact. Never rejects.
   */
  async start(): Promise<void> {
    return new Promise<void>((resolve) => {
      // allowHalfOpen: the peer half-closes its write side after sending one
      // frame (socket.end(body)); we still need our write side open to send
      // the ack/nack back. Without this the kernel auto-ends our writable side
      // on the peer's FIN and the async ack write throws write-after-end.
      const server = createServer({ allowHalfOpen: true }, (socket) => {
        this.handleConnection(socket);
      });

      // SAFETY: a malformed-peer or reset connection raises 'error' on the
      // socket, which without a handler crashes the process. We handle it per
      // socket in handleConnection; this server-level guard catches the rest.
      server.on("error", (err: NodeJS.ErrnoException) => {
        if (this.server === null) {
          // Error during bind: loud warning, never throw, never retry-loop.
          this.warn(
            `[SANCTUARY DISTRESS] local listener could NOT bind ` +
              `${this.host}:${this.port} (${err.code ?? err.message}). ` +
              `The in-process distress lane (stderr + audit) is unaffected; ` +
              `only the local network leg is unavailable. ` +
              `If another process holds the port, free it and restart the dashboard.`,
          );
          resolve();
        } else {
          // Post-bind transient server error: log, keep serving.
          this.warn(
            `[SANCTUARY DISTRESS] local listener transient error: ${err.message}`,
          );
        }
      });

      server.listen(this.port, this.host, () => {
        this.server = server;
        // maxConnections gives the kernel-level backpressure; we also count
        // in-flight handlers for the immediate-destroy guard.
        server.maxConnections = DISTRESS_MAX_CONNECTIONS;
        resolve();
      });
    });
  }

  /** The bound port (useful after an ephemeral :0 bind in tests). */
  address(): { port: number; host: string } | null {
    const addr = this.server?.address();
    if (addr === null || addr === undefined || typeof addr === "string") {
      return null;
    }
    return { port: addr.port, host: addr.address };
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    if (!server) return;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  private handleConnection(socket: Socket): void {
    if (this.activeConnections >= DISTRESS_MAX_CONNECTIONS) {
      socket.destroy();
      return;
    }
    this.activeConnections += 1;

    let buf = "";
    let total = 0;
    let counted = true;
    let aborted = false;
    let helloSeen = false;
    let serverNonce: string | null = null;

    // Mint this connection's server nonce. It is registered as live only AFTER
    // the emitter's hello, so a peer that connects and stalls without a hello
    // never parks a nonce.
    const releaseNonce = (): void => {
      if (serverNonce !== null) {
        this.liveNonces.delete(serverNonce);
        serverNonce = null;
      }
    };

    // Release the connection slot + nonce exactly once, when the socket closes.
    socket.once("close", () => {
      if (counted) {
        counted = false;
        this.activeConnections -= 1;
      }
      releaseNonce();
    });

    // Abort path: tear the socket down hard (oversized / timeout / error).
    const abort = (): void => {
      if (aborted) return;
      aborted = true;
      releaseNonce();
      socket.destroy();
    };

    // Bounded read window: a stalling peer is dropped so it can't hold the
    // socket open and tie up a connection slot.
    socket.setTimeout(DISTRESS_CONN_TIMEOUT_MS, () => {
      abort();
    });

    // A socket 'error' (reset, etc.) must not crash the process.
    socket.on("error", () => {
      abort();
    });

    socket.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > DISTRESS_FRAME_MAX_BYTES) {
        // Hostile/oversized peer: nack and drop without buffering more.
        this.writeNack(socket, "too_large");
        void this.auditRejection("too_large");
        abort();
        return;
      }
      buf += chunk.toString("utf8");

      // Phase 1: the emitter's hello (one newline-terminated line) carrying a
      // fresh client nonce. The listener's proof binds that client nonce, so a
      // pre-harvested challenge cannot be replayed to the emitter (codex
      // round-2 HIGH). Until the hello lands, no nonce is registered.
      if (!helloSeen) {
        const nl = buf.indexOf("\n");
        if (nl === -1) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        helloSeen = true;

        let hello: DistressClientHello;
        try {
          hello = JSON.parse(line) as DistressClientHello;
        } catch {
          this.writeNack(socket, "malformed");
          abort();
          return;
        }
        if (
          hello.protocol !== "sanctuary.distress.local.v1" ||
          typeof hello.client_nonce !== "string" ||
          hello.client_nonce.length === 0 ||
          hello.client_nonce.length > 256
        ) {
          this.writeNack(socket, "malformed");
          abort();
          return;
        }

        serverNonce = randomBytes(NONCE_BYTES).toString("hex");
        this.liveNonces.add(serverNonce);
        const challenge: DistressChallenge = {
          protocol: "sanctuary.distress.local.v1",
          nonce: serverNonce,
          proof: computeChallengeProof(
            hello.client_nonce,
            serverNonce,
            this.localSecret,
          ),
        };
        if (socket.writable) {
          socket.write(`${JSON.stringify(challenge)}\n`);
        }
      }
      // Phase 2 bytes (the frame) accumulate in buf until 'end'.
    });

    socket.on("end", () => {
      if (aborted) return;
      if (!helloSeen || serverNonce === null) {
        // Peer closed before completing the hello: nothing to ingest.
        this.writeNack(socket, "malformed");
        return;
      }
      const frameNonce = serverNonce;
      void this.ingest(buf, frameNonce)
        .then((outcome) => {
          releaseNonce();
          if (outcome.ok) {
            this.writeAck(socket, outcome.event_id);
          } else {
            this.writeNack(socket, outcome.reason);
          }
        })
        .catch(() => {
          releaseNonce();
          this.writeNack(socket, "store_failed");
        });
    });
  }

  /**
   * Parse, authenticate, validate, and store one delivery frame against the
   * issued connection nonce. Returns the outcome; never throws to the caller.
   * NOTE: information leak guard — the ack/nack carries ONLY a status (+ the
   * event_id the peer itself sent), never any stored-inbox content.
   */
  async ingest(raw: string, nonce: string): Promise<DeliveryOutcome> {
    if (raw.length > DISTRESS_FRAME_MAX_BYTES) {
      await this.auditRejection("too_large");
      return { ok: false, reason: "too_large" };
    }

    // The nonce must be one we issued and have not yet consumed. A frame that
    // does not carry a live nonce (replayed, or never challenged) is rejected
    // before any crypto work.
    if (!this.liveNonces.has(nonce)) {
      await this.auditRejection("replay");
      return { ok: false, reason: "replay" };
    }

    let frame: DistressDeliveryFrame;
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (
        typeof parsed !== "object" ||
        parsed === null ||
        typeof (parsed as DistressDeliveryFrame).hmac !== "string" ||
        typeof (parsed as DistressDeliveryFrame).envelope_hash !== "string"
      ) {
        await this.auditRejection("malformed");
        return { ok: false, reason: "malformed" };
      }
      frame = parsed as DistressDeliveryFrame;
    } catch {
      await this.auditRejection("malformed");
      return { ok: false, reason: "malformed" };
    }

    // Closed envelope shape FIRST — never trust peer structure.
    if (!isValidEnvelope(frame.envelope)) {
      await this.auditRejection("bad_envelope");
      return { ok: false, reason: "bad_envelope" };
    }

    // Sender authentication: HMAC over (domain || nonce || canonical envelope).
    // The envelope_hash is also recomputed so a peer cannot ship a hash that
    // disagrees with the bytes it signed.
    const expectedHmac = computeFrameHmac(frame.envelope, nonce, this.localSecret);
    if (!hmacEquals(expectedHmac, frame.hmac)) {
      await this.auditRejection("bad_signature", frame.envelope.event_id);
      return { ok: false, reason: "bad_signature" };
    }
    const recomputedHash = sha256(canonicalJson(frame.envelope));
    if (recomputedHash !== frame.envelope_hash) {
      // Authenticated bytes but a mismatched advertised hash: treat as
      // malformed (the signed bytes are what we store; the disagreement is a
      // bug or tamper attempt on the non-signed hash field).
      await this.auditRejection("malformed", frame.envelope.event_id);
      return { ok: false, reason: "malformed" };
    }

    // Consume the nonce: it is single-use. Even if the same frame is somehow
    // re-submitted on this connection, the nonce is now gone.
    this.liveNonces.delete(nonce);

    // Cross-connection replay defense: reject an event_id we already accepted.
    if (this.seenEventIds.has(frame.envelope.event_id)) {
      await this.auditRejection("replay", frame.envelope.event_id);
      return { ok: false, reason: "replay" };
    }

    try {
      await this.inbox.append({
        envelope: frame.envelope,
        envelope_hash: recomputedHash,
        received_at: new Date(this.now()).toISOString(),
        authenticated: true,
      });
    } catch {
      await this.auditRejection("store_failed", frame.envelope.event_id);
      return { ok: false, reason: "store_failed" };
    }

    // Remember this event_id for cross-connection replay defense, bounded.
    this.seenEventIds.add(frame.envelope.event_id);
    if (this.seenEventIds.size > DISTRESS_SEEN_EVENTS_MAX) {
      const oldest = this.seenEventIds.values().next().value;
      if (oldest !== undefined) this.seenEventIds.delete(oldest);
    }

    await this.auditLog.appendCritical({
      layer: "l2",
      operation: "sanctuary_distress_local_received",
      identity_id: this.identityId,
      result: "success",
      details: {
        event_id: frame.envelope.event_id,
        reason: frame.envelope.reason,
        severity: frame.envelope.severity,
        envelope_hash: recomputedHash,
      },
    });

    return { ok: true, event_id: frame.envelope.event_id };
  }

  private async auditRejection(
    reason: DeliveryRejection,
    eventId?: string,
  ): Promise<void> {
    try {
      await this.auditLog.appendCritical({
        layer: "l2",
        operation: "sanctuary_distress_local_rejected",
        identity_id: this.identityId,
        result: "failure",
        details: {
          rejection: reason,
          ...(eventId !== undefined ? { claimed_event_id: eventId } : {}),
        },
      });
    } catch {
      // Audit of a rejection is best-effort; never let it throw out of the
      // connection handler.
    }
  }

  private writeAck(socket: Socket, eventId: string): void {
    if (!socket.writable) return;
    try {
      // Status only — NO inbox content. The event_id echoed is the one the
      // peer itself just sent, so this discloses nothing new.
      socket.end(JSON.stringify({ ok: true, event_id: eventId }));
    } catch {
      // ignore write-after-close
    }
  }

  private writeNack(socket: Socket, reason: string): void {
    if (!socket.writable) return;
    try {
      socket.end(JSON.stringify({ ok: false, reason }));
    } catch {
      // ignore
    }
  }
}
