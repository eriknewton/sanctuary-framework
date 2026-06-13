/**
 * Phase S1 — Supervisor local-socket server (supervisor side).
 *
 * Binds an `AF_UNIX` socket the dashboard connects to. Three layers gate it,
 * matching protocol.ts's stated model:
 *
 *   1. operator-uid-only — the socket is created inside a directory the
 *      caller has pre-created mode 0700 and owned by the operator uid, and the
 *      socket file itself is chmod'd 0600. On a POSIX system the kernel's
 *      filesystem permission check is the primary uid gate: a process running
 *      as a different uid cannot `connect()` to a 0600 socket in a 0700 dir.
 *      Node does not expose SO_PEERCRED, so filesystem confinement IS the uid
 *      boundary (this is the same mechanism the SSH agent socket relies on).
 *   2. authenticated — every frame carries an HMAC over its bytes keyed by the
 *      per-boot secret the dashboard handed the supervisor at spawn (env, not
 *      disk). A frame whose MAC fails is dropped and the connection closed —
 *      defence in depth against a same-uid process that found the path.
 *   3. bounded — frames are length-prefixed and capped (FrameDecoder); an
 *      over-long prefix closes the connection before any allocation. A
 *      per-connection read budget caps total bytes so a slow-loris or a flood
 *      cannot pin memory.
 *
 * The transient key only ever arrives inside a MAC-verified, length-bounded
 * protect frame. It is never logged. The handler is injected so the wire
 * plumbing is separable from the Supervisor lifecycle.
 */

import { createServer, type Server, type Socket } from "node:net";
import { chmodSync, statSync } from "node:fs";
import { rm } from "node:fs/promises";
import {
  FrameDecoder,
  encodeFrame,
  parseRequest,
  MAX_FRAME_BYTES,
  FRAME_HEADER_BYTES,
  type SupervisorRequest,
  type SupervisorResponse,
} from "./protocol.js";

/** Cap on total bytes a single connection may send before one full frame. */
const PER_CONNECTION_READ_BUDGET = MAX_FRAME_BYTES + FRAME_HEADER_BYTES;

export interface SocketServerDeps {
  /** Absolute path to the `AF_UNIX` socket. Must sit in a 0700 operator dir. */
  socketPath: string;
  /** Per-boot shared auth secret (from {@link mintAuthSecret}). */
  authSecret: Uint8Array;
  /** Handle one verified request, producing the response to send back. */
  handle: (req: SupervisorRequest) => Promise<SupervisorResponse>;
  /** Structured log sink (never receives the transient key). */
  log?: (event: string, fields?: Record<string, unknown>) => void;
}

export class SupervisorSocketServer {
  private server: Server | null = null;
  private readonly deps: SocketServerDeps;

  constructor(deps: SocketServerDeps) {
    this.deps = deps;
  }

  /**
   * Bind the socket. The caller MUST have created the parent directory mode
   * 0700 owned by the operator uid before calling; this method additionally
   * verifies the parent dir is not group/other-accessible and chmods the
   * socket file 0600 after bind. Refuses to bind (throws) if the parent dir
   * is world/group accessible — fail closed rather than expose the socket.
   */
  async listen(): Promise<void> {
    const dir = this.deps.socketPath.replace(/\/[^/]+$/, "");
    const st = statSync(dir);
    // Reject a parent dir that grants any group/other permission bit. 0o077
    // masks group+other rwx; a 0700 dir leaves zero bits here.
    if ((st.mode & 0o077) !== 0) {
      throw new Error(
        `supervisor socket dir ${dir} is group/other-accessible (mode ${(st.mode & 0o777).toString(8)}); refusing to bind`,
      );
    }
    // Ownership is part of the uid-confinement invariant (codex M1): a 0700
    // dir owned by a DIFFERENT uid does not confine to the operator. Require
    // the dir to be owned by this process's uid before binding. (process.getuid
    // is absent on Windows, where AF_UNIX confinement differs; skip the check
    // there rather than fail a platform that has no uid concept.)
    if (typeof process.getuid === "function") {
      const myUid = process.getuid();
      if (st.uid !== myUid) {
        throw new Error(
          `supervisor socket dir ${dir} is owned by uid ${st.uid}, not ${myUid}; refusing to bind`,
        );
      }
    }
    // Clean a stale socket from a previous boot (EADDRINUSE otherwise).
    await rm(this.deps.socketPath, { force: true });

    const server = createServer((socket) => this.onConnection(socket));
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.deps.socketPath, () => {
        server.removeListener("error", reject);
        try {
          // Belt-and-suspenders: lock the socket file to the owner only.
          chmodSync(this.deps.socketPath, 0o600);
        } catch {
          // chmod failure on a non-POSIX fs is non-fatal; the 0700 dir still
          // confines. Log via the caller's sink if present.
          this.deps.log?.("socket.chmod_failed", { path: this.deps.socketPath });
        }
        resolve();
      });
    });
  }

  async close(): Promise<void> {
    const server = this.server;
    this.server = null;
    if (!server) return;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(this.deps.socketPath, { force: true });
  }

  private onConnection(socket: Socket): void {
    const decoder = new FrameDecoder(this.deps.authSecret);
    let bytesRead = 0;
    let handling = false;

    const fail = (reason: string): void => {
      this.deps.log?.("socket.connection_dropped", { reason });
      socket.destroy();
    };

    socket.on("data", (chunk: Buffer) => {
      bytesRead += chunk.length;
      if (bytesRead > PER_CONNECTION_READ_BUDGET) {
        fail("read_budget_exceeded");
        return;
      }
      // One request per connection (request/response then close). If a frame
      // is already being handled, any further bytes are unexpected.
      if (handling) {
        fail("unexpected_extra_bytes");
        return;
      }
      const outcome = decoder.push(chunk);
      if (outcome.status === "incomplete") return;
      if (outcome.status === "error") {
        fail(`frame_${outcome.reason}`);
        return;
      }
      // A full, MAC-verified frame. Validate shape, then handle.
      const req = parseRequest(outcome.message);
      if (!req) {
        // Respond with a generic bad_request (the MAC already proved the peer
        // holds the secret, so a shape error is honest, not an oracle).
        this.respond(socket, { ok: false, kind: "error", reason: "bad_request" });
        return;
      }
      handling = true;
      void this.deps
        .handle(req)
        .then((resp) => this.respond(socket, resp))
        .catch(() => this.respond(socket, { ok: false, kind: "error", reason: "unavailable" }));
    });

    socket.on("error", () => socket.destroy());
    // A connection that sends nothing is reaped by the socket timeout.
    socket.setTimeout(10_000, () => fail("idle_timeout"));
  }

  private respond(socket: Socket, resp: SupervisorResponse): void {
    try {
      socket.end(encodeFrame(this.deps.authSecret, resp));
    } catch {
      socket.destroy();
    }
  }
}
