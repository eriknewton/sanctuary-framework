/**
 * The gate-daemon-side CLIENT for the privileged peer-uid resolver (Unified
 * Protect Slice 5 S5-3 fix, Option 1 -- see `peer-resolver-daemon.ts` for the
 * server this talks to and the full root-cause writeup).
 *
 * THE SEAM THIS FILLS. `gate-server.ts` / `peer-identity.ts` consume a
 * {@link PeerCommandRunner}: `run(command, args) -> {code, stdout}`, exactly
 * shaped like an `execFile("lsof", [...])` result. `createPrivilegedPeerRunner`
 * IMPLEMENTS that exact interface, so `gate-daemon.ts` swaps ONE line
 * (`createExecFilePeerRunner()` -> `createPrivilegedPeerRunner(...)`) and
 * `peer-identity.ts`'s `resolveLoopbackPeer`/`parseLsofPeer` -- the PURE
 * decision functions the build spec says must stay untouched -- never change
 * at all. Internally, instead of spawning `lsof` locally (which cannot see a
 * different uid's socket), this dials the root resolver over its per-agent
 * Unix domain socket and SYNTHESIZES an lsof-`-Fpun`-shaped `stdout` string
 * from the resolver's structured answer, so the exact same parser the gate
 * has always used still does the parsing.
 *
 * FAIL-CLOSED BY CONSTRUCTION, NEVER A THROW. Every failure mode (connection
 * refused because the resolver daemon is down, a timeout, a malformed
 * response, an `ok:false` answer, even a caller passing an unexpected
 * command/argv shape) resolves -- never rejects -- with the SAME synthetic
 * non-zero exit `exec-runner.ts` already uses for a spawn failure (`code:
 * 127`, empty stdout). `resolveLoopbackPeer`'s existing `result.code !== 0 ->
 * null` handling (unmodified) then treats it as `unresolved`, which S5-3
 * denies. So "resolver unreachable/timeout" structurally can only ever
 * produce a deny, by reusing logic this codebase already has full coverage
 * on -- there is no new branch here that could silently allow.
 */

import { createConnection, type Socket } from "node:net";

import {
  PEER_RESOLVER_MAX_FRAME_BYTES,
  encodePeerResolveRequest,
  parsePeerResolveResponse,
} from "./peer-resolver-protocol.js";
import { peerResolverSocketPath } from "./peer-resolver-daemon.js";
import type { PeerCommandRunner } from "./peer-identity.js";

/** Default hard timeout for one resolve round trip (mirrors PEER_LOOKUP_TIMEOUT_MS). */
export const PRIVILEGED_PEER_RUNNER_TIMEOUT_MS = 2_000;

/** The synthetic non-zero exit code used for every transport/protocol failure. */
const SYNTHETIC_FAILURE_CODE = 127;

const FAILURE_RESULT = { code: SYNTHETIC_FAILURE_CODE, stdout: "" } as const;

export interface PrivilegedPeerRunnerOptions {
  /** The confined agent uid this gate serves (selects the resolver socket). */
  agentUid: number;
  /**
   * THIS gate's own committed port (fix-round BLOCKER; `policy.gate_port` at
   * the `gate-daemon.ts` wiring site). REQUIRED -- embedded into the
   * synthesized lsof-shaped stdout as the REMOTE endpoint so it survives the
   * round trip through the UNCHANGED, now full-4-tuple-matching
   * `parseLsofPeer` (`peer-identity.ts`). Sourced from the gate daemon's own
   * loaded+validated policy, never from anything the resolver daemon's
   * answer itself carries.
   */
  gatePort: number;
  /** Socket path override (default: {@link peerResolverSocketPath}(agentUid)). */
  socketPath?: string;
  /** Round-trip timeout override. */
  timeoutMs?: number;
  /** Injectable transport for tests (default: `net.createConnection`). */
  connect?: (path: string) => Socket;
}

/** Extract the client port from the args this codebase's lsof invocation always uses. */
function extractClientPort(args: readonly string[]): number | null {
  if (args.length !== 3 || args[0] !== "-nP" || args[1] !== "-Fpun") return null;
  const m = /^-iTCP@127\.0\.0\.1:(\d+)$/.exec(args[2] ?? "");
  if (!m) return null;
  const port = Number(m[1]);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
}

/**
 * Synthesize the minimal lsof-`-Fpun`-shaped stdout `parseLsofPeer` expects.
 * `gatePort` is THIS caller's own gate port (never the resolver's answer),
 * embedded as the remote endpoint so the full-4-tuple match in
 * `parseLsofPeer` (fix-round BLOCKER) succeeds for a genuinely-scoped
 * resolver answer.
 */
function synthesizeLsofStdout(clientPort: number, peer: { uid: number; pid: number }, gatePort: number): string {
  return [`p${peer.pid}`, `u${peer.uid}`, `n127.0.0.1:${clientPort}->127.0.0.1:${gatePort}`, ""].join("\n");
}

/**
 * Build a {@link PeerCommandRunner} that resolves loopback peers through the
 * privileged resolver daemon instead of a local (unprivileged, cross-uid-blind)
 * `lsof`. Drop-in for `createExecFilePeerRunner()` at the `gate-daemon.ts`
 * wiring site; `peer-identity.ts` and `gate-server.ts` need no changes.
 */
export function createPrivilegedPeerRunner(options: PrivilegedPeerRunnerOptions): PeerCommandRunner {
  if (!Number.isInteger(options.agentUid) || options.agentUid <= 0) {
    throw new Error(`privileged peer runner: agent uid must be a positive integer (got ${String(options.agentUid)})`);
  }
  if (!Number.isInteger(options.gatePort) || options.gatePort < 1 || options.gatePort > 65535) {
    throw new Error(`privileged peer runner: gate port must be a valid TCP port (got ${String(options.gatePort)})`);
  }
  const gatePort = options.gatePort;
  const socketPath = options.socketPath ?? peerResolverSocketPath(options.agentUid);
  const timeoutMs = options.timeoutMs ?? PRIVILEGED_PEER_RUNNER_TIMEOUT_MS;
  const connect = options.connect ?? ((path: string): Socket => createConnection(path));

  return {
    run(command: string, args: readonly string[]): Promise<{ code: number; stdout: string }> {
      // Defensive scope check (Codex-lens hardening): this runner ONLY ever
      // proxies the ONE lsof invocation shape this codebase issues. Anything
      // else is a caller bug, not a request to relay -- fail closed rather
      // than dial the resolver with an unexpected command.
      if (command !== "lsof") return Promise.resolve(FAILURE_RESULT);
      const clientPort = extractClientPort(args);
      if (clientPort === null) return Promise.resolve(FAILURE_RESULT);

      return new Promise((resolve) => {
        let settled = false;
        const settle = (result: { code: number; stdout: string }): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          socket.destroy();
          resolve(result);
        };
        let socket: Socket;
        try {
          socket = connect(socketPath);
        } catch {
          resolve(FAILURE_RESULT);
          return;
        }
        const timer = setTimeout(() => settle(FAILURE_RESULT), timeoutMs);
        // A connect()/timeout timer must never keep the process alive.
        if (typeof (timer as unknown as { unref?: () => void }).unref === "function") {
          (timer as unknown as { unref: () => void }).unref();
        }
        let buffer = "";
        socket.on("connect", () => {
          try {
            socket.write(encodePeerResolveRequest({ v: 1, clientPort }));
          } catch {
            settle(FAILURE_RESULT);
          }
        });
        socket.on("data", (chunk: Buffer) => {
          if (settled) return;
          buffer += chunk.toString("utf8");
          if (Buffer.byteLength(buffer, "utf8") > PEER_RESOLVER_MAX_FRAME_BYTES) {
            settle(FAILURE_RESULT);
            return;
          }
          const nl = buffer.indexOf("\n");
          if (nl === -1) return;
          const resp = parsePeerResolveResponse(buffer.slice(0, nl));
          if (resp === null || resp.ok !== true) {
            settle(FAILURE_RESULT);
            return;
          }
          if (resp.peer === null) {
            settle({ code: 0, stdout: "" });
            return;
          }
          settle({ code: 0, stdout: synthesizeLsofStdout(clientPort, resp.peer, gatePort) });
        });
        socket.on("error", () => settle(FAILURE_RESULT));
        socket.on("close", () => settle(FAILURE_RESULT));
      });
    },
  };
}
