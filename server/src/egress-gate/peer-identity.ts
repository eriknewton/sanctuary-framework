/**
 * Loopback-TCP peer-identity recovery (Unified Protect Slice 2; RECONCILED
 * 2026-07-24 for the S5-3 fail-closed contract, `Gate_Peer_Resolution_Fix_
 * Build_Spec_2026-07-24.md`).
 *
 * The gate channel pivoted from UDS to loopback TCP (Wave-A Q1) to keep
 * standard `HTTPS_PROXY`-over-TCP compatibility ("works with any
 * agent/harness"; a UDS proxy socket needs client support almost nothing
 * has). That pivot cost the easy `getpeereid` peer-uid read. This module
 * recovers the connecting client's pid/uid by mapping the loopback 4-tuple
 * back to the owning process.
 *
 * THIS MODULE'S OWN CONTRACT IS UNCHANGED AND POLICY-NEUTRAL: `null` means
 * only "could not resolve," never a decision. WHAT A CALLER DOES WITH `null`
 * DEPENDS ENTIRELY ON WHICH GATE MODE IS ASKING -- there are now TWO, and a
 * stale single-mode framing here previously read as a universal truth it was
 * not:
 *
 *   - LEGACY / ADVISORY MODE (Slice 2, `gate-server.ts`'s branch when no
 *     `clientAuth` is configured): a MISMATCH is logged loudly but the
 *     request is still policy-evaluated on its own merits; a MATCH never
 *     grants anything by itself; an unresolved `null` is surfaced as an
 *     event, NOT a deny (the fail-closed control in this mode is the pf
 *     liveness check, not peer identity).
 *   - FAIL-CLOSED / TCB MODE (Slice 5 S5-3, `gate-client-auth.ts`, the
 *     production wiring since S5-6): peer identity is a REQUIRED second
 *     lens. The SAME `null` this module returns is a HARD DENY there
 *     (`peer_unresolved`) -- bearer credential alone never overrides it.
 *
 * THE 2026-07-24 DRILL FINDING, for why this reconciliation exists: in TCB
 * mode, an UNPRIVILEGED gate uid running `lsof` cannot see a DIFFERENT uid's
 * socket, so this module's `resolveLoopbackPeer` returned `null` on EVERY
 * real agent CONNECT (100%, hardware-confirmed), and S5-3's fail-closed
 * `null -> deny` rule strangled the agent completely. The fix
 * (`peer-resolver-client.ts` / `peer-resolver-daemon.ts`) does not touch this
 * module's decision logic at all -- `parseLsofPeer` and `resolveLoopbackPeer`
 * are UNCHANGED and reused server-side by the new privileged resolver too. It
 * changes only WHICH `PeerCommandRunner` production TCB wiring injects: a
 * client that dials a root-owned resolver instead of shelling `lsof` locally,
 * so the SAME lookup that used to fail 100% of the time now succeeds for the
 * common case, and `null` genuinely means the rare race/TOCTOU case again.
 *
 * MECHANISM (minimalism ladder): the platform's `lsof` is shelled out to
 * (never a shell string, argv only) instead of adding a native `libproc`
 * dependency. `lsof -nP -Fpun -iTCP@127.0.0.1:<port>` prints the owning
 * pid/uid of every socket on that port; the entry whose LOCAL endpoint is
 * the client's ephemeral port (its name field starts
 * `127.0.0.1:<clientPort>->`) is the peer. The gate's own socket on the
 * same connection has the inverse orientation and is skipped. DEBT: a
 * `proc_pidinfo`/`PROC_PIDFDSOCKETINFO` native path would avoid the lsof
 * dependency (in BOTH the legacy in-process caller and the privileged
 * resolver daemon) at the cost of a native module; the 2026-07-24 fix ships
 * root-`lsof` as the interim mechanism (per spec, acceptable to ship first)
 * and files the native path as a follow-on, deferred until a drill shows
 * `lsof` is too slow or unreliable.
 *
 * Drill acceptance (design Slice 2 criterion: resolves the agent uid for a
 * real agent connection and a non-agent uid for an operator connection,
 * N>=3) is PENDING -- see `Mini1_S5_PositiveThroughGate_Drill_Runbook_2026-07-23.md`;
 * this is the Erik-present DoD for the 2026-07-24 fix, not proven by this
 * module's own (host-free) unit tests.
 */

import { createExecFileRunner } from "./exec-runner.js";

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

/**
 * Production runner: execFile with a hard timeout, argv only (no shell).
 * Shared implementation: `exec-runner.ts` (peer callers read code/stdout
 * only; the extra stderr field is ignored).
 */
export function createExecFilePeerRunner(
  timeoutMs: number = PEER_LOOKUP_TIMEOUT_MS,
): PeerCommandRunner {
  return createExecFileRunner(timeoutMs);
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
 * determined (lsof missing, raced socket, unparseable output). THIS FUNCTION
 * never blocks anything itself -- it only reports `null` or a resolved
 * identity. Whether a caller's `null` becomes a deny depends on the calling
 * gate mode (see the module header): advisory in the legacy Slice 2 path,
 * a hard `peer_unresolved` deny in the S5-3 TCB path.
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
