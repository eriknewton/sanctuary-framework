/**
 * Loopback-TCP peer-identity recovery (Unified Protect Slice 2).
 *
 * The gate channel pivoted from UDS to loopback TCP (Wave-A Q1), which cost
 * the easy `getpeereid` peer-uid read. This module recovers the connecting
 * client's pid/uid by mapping the loopback 4-tuple back to the owning
 * process.
 *
 * STANCE: ADVISORY-ONLY (design open-decision 3, CTO-confirmed). The
 * PRIMARY control is the kernel wall confinement (per-uid classification at
 * the sysext) plus the pf loopback anchor; peer identity at the gate is a
 * second lens. There is an inherent TOCTOU window: the client socket can
 * close and its ephemeral port be reused between `accept()` and the query.
 * The window is DOCUMENTED, not fixed; consequently:
 *
 *   - a peer-uid MISMATCH is logged loudly (audit event) but the request is
 *     still policy-evaluated on its own merits;
 *   - a peer-uid MATCH never grants anything by itself (never grant on
 *     peer-id alone);
 *   - a resolution failure resolves to `null` and the gate proceeds on the
 *     primary controls (the failure is surfaced as an event, not a deny,
 *     because peer-id is advisory; the fail-closed control is the pf
 *     liveness check in `gate-server.ts`).
 *
 * MECHANISM (minimalism ladder): the platform's `lsof` is shelled out to
 * (never a shell string, argv only) instead of adding a native `libproc`
 * dependency. `lsof -nP -Fpun -iTCP@127.0.0.1:<port>` prints the owning
 * pid/uid of every socket on that port; the entry whose LOCAL endpoint is
 * the client's ephemeral port (its name field starts
 * `127.0.0.1:<clientPort>->`) is the peer. The gate's own socket on the
 * same connection has the inverse orientation and is skipped. DEBT: a
 * `proc_pidinfo`/`PROC_PIDFDSOCKETINFO` native path would avoid the lsof
 * dependency at the cost of a native module; deferred until a drill shows
 * lsof is too slow or unreliable.
 *
 * Drill acceptance (design Slice 2 criterion: resolves the agent uid for a
 * real agent connection and a non-agent uid for an operator connection,
 * N>=3) is PENDING.
 */

import { execFile } from "node:child_process";

/** A resolved loopback peer. */
export interface LoopbackPeerIdentity {
  pid: number;
  uid: number;
}

/** Command abstraction so tests can inject lsof output. */
export interface PeerCommandRunner {
  run(command: string, args: readonly string[]): Promise<{ code: number; stdout: string }>;
}

/** Default hard timeout for one lsof invocation. */
export const PEER_LOOKUP_TIMEOUT_MS = 2_000;

/** Production runner: execFile with a hard timeout, argv only (no shell). */
export function createExecFilePeerRunner(
  timeoutMs: number = PEER_LOOKUP_TIMEOUT_MS,
): PeerCommandRunner {
  return {
    run(command: string, args: readonly string[]): Promise<{ code: number; stdout: string }> {
      return new Promise((resolve) => {
        execFile(command, [...args], { timeout: timeoutMs, encoding: "utf8" }, (error, stdout) => {
          if (error && typeof (error as NodeJS.ErrnoException).code !== "number") {
            resolve({ code: 127, stdout: stdout ?? "" });
            return;
          }
          const code = error ? ((error as NodeJS.ErrnoException).code as unknown as number) : 0;
          resolve({ code: typeof code === "number" ? code : 127, stdout });
        });
      });
    },
  };
}

/**
 * Parse `lsof -Fpun` field output into per-process socket records and find
 * the one whose LOCAL endpoint is `127.0.0.1:<clientPort>`.
 *
 * lsof field format: each process starts with `p<pid>`, followed by
 * `u<uid>` and one or more file sets whose network name field is
 * `n<local>-><remote>` (or `n<local>` for a listener). Exported for tests.
 */
export function parseLsofPeer(
  output: string,
  clientPort: number,
  selfPid: number,
): LoopbackPeerIdentity | null {
  let pid: number | null = null;
  let uid: number | null = null;
  const localPrefix = `127.0.0.1:${clientPort}->`;
  for (const line of output.split("\n")) {
    if (line.length === 0) continue;
    const tag = line[0];
    const rest = line.slice(1);
    if (tag === "p") {
      const parsed = Number(rest);
      pid = Number.isInteger(parsed) ? parsed : null;
      uid = null;
    } else if (tag === "u") {
      const parsed = Number(rest);
      uid = Number.isInteger(parsed) ? parsed : null;
    } else if (tag === "n") {
      if (
        rest.startsWith(localPrefix) &&
        pid !== null &&
        uid !== null &&
        pid !== selfPid
      ) {
        return { pid, uid };
      }
    }
  }
  return null;
}

/** Options for {@link resolveLoopbackPeer}. */
export interface ResolveLoopbackPeerOptions {
  /** The connected client's ephemeral port (socket.remotePort). */
  clientPort: number;
  /** Our own pid, excluded from candidates (defaults to process.pid). */
  selfPid?: number;
  runner?: PeerCommandRunner;
}

/**
 * Resolve the loopback peer's pid/uid, or `null` when it cannot be
 * determined (lsof missing, raced socket, unparseable output). `null` NEVER
 * blocks the request: peer identity is advisory (see module header).
 */
export async function resolveLoopbackPeer(
  options: ResolveLoopbackPeerOptions,
): Promise<LoopbackPeerIdentity | null> {
  const { clientPort } = options;
  if (!Number.isInteger(clientPort) || clientPort < 1 || clientPort > 65535) {
    return null;
  }
  const runner = options.runner ?? createExecFilePeerRunner();
  const selfPid = options.selfPid ?? process.pid;
  let result: { code: number; stdout: string };
  try {
    result = await runner.run("lsof", ["-nP", "-Fpun", `-iTCP@127.0.0.1:${clientPort}`]);
  } catch {
    return null;
  }
  if (result.code !== 0) {
    return null;
  }
  return parseLsofPeer(result.stdout, clientPort, selfPid);
}
