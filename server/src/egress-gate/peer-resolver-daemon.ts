/**
 * The privileged peer-uid resolver DAEMON (Unified Protect Slice 5 S5-3 fix,
 * Option 1 -- `Gate_Peer_Resolution_Fix_Build_Spec_2026-07-24.md`).
 *
 * WHY THIS EXISTS. The exclusive-egress gate's second auth lens needs "what
 * uid owns this loopback TCP port" (`peer-identity.ts`), but the gate daemon
 * that would ask is deliberately UNPRIVILEGED (`gate-daemon.ts`'s own header:
 * "the gate is TCB but must never hold root"). A non-root `lsof` cannot see a
 * different uid's socket, so that lookup was returning `null` on every real
 * agent connect (Mini1 2026-07-24 drill, hardware-confirmed: `lsof -p` as the
 * gate uid -> 0 fds; as root -> 8 fds) and the S5-3 fail-closed rule denies on
 * every unresolved peer -- the gate strangled its own agent 100% of the time.
 *
 * THE FIX. A NARROW root-owned LaunchDaemon, ONE PER CONFINED AGENT (mirrors
 * `gate-daemon.ts`'s own "one daemon per confined agent" process shape, just
 * root instead of the gate service account), answers exactly one question
 * over a per-agent-uid-scoped Unix domain socket: "what uid/pid owns loopback
 * client port N" (`peer-resolver-protocol.ts`). It does NOT run arbitrary
 * commands, does NOT accept a `command`/`argv` field from the wire, and does
 * NOT expose a general port->uid map -- the wire protocol itself has no field
 * that could carry one.
 *
 * SCOPING (the security-sensitive core; the two-family adversarial gate
 * focuses here):
 *   - INVOCABLE ONLY BY THE GATE UID. Node exposes no `SO_PEERCRED`/
 *     `getpeereid` (the same gap `supervisor/socket-server.ts` documents), so
 *     the boundary is filesystem permission: the parent dir is root 0711
 *     (traversal without listing, mirrors `GATE_LIVENESS_DIR`), and the
 *     socket FILE is root-created then CHOWNED to the one gate uid it serves,
 *     mode 0600 -- a different uid's `connect()` gets EPERM at the kernel,
 *     never reaching this process's code at all.
 *   - RATE-LIMITED. A concurrency cap on in-flight `lsof` executions (this
 *     process now pays the root-subprocess-amplification cost the OLD design
 *     worried about the gate paying as itself -- see `PEER_RESOLVER_MAX_
 *     CONCURRENT_LOOKUPS`); over the cap, a request is answered
 *     `rate_limited` (a bounded error, not a hang, not a queue that could
 *     grow unbounded).
 *   - AUDITED. Every request is logged (port, outcome, latency) through the
 *     SAME `onEvent`-to-stderr convention every daemon in this family uses
 *     (`gate-daemon.ts`'s `[egress-gate] ...` line).
 *   - THE MINIMUM ANSWER. The response carries `{uid, pid}` (not a full
 *     process/environment dump) so the calling gate daemon can still produce
 *     its existing `peer_uid_mismatch` audit fields; it never returns
 *     information about a port the caller did not ask about.
 *
 * MECHANISM (interim, per the build spec): `lsof` run AS ROOT via the SAME
 * `PeerCommandRunner`/`parseLsofPeer` pair `peer-identity.ts` already uses --
 * this reuses the exact tested parse logic instead of forking it. DEBT: the
 * native `proc_pidinfo`/`PROC_PIDFDSOCKETINFO` path (no subprocess spawn per
 * lookup) is the target end state; `peer-identity.ts`'s header already
 * tracked this DEBT for the pre-privilege design and it is UNCHANGED here --
 * shelling `lsof` as root is still a subprocess-per-lookup cost, now paid by
 * root instead of failing outright. Ship interim first (this build); file the
 * native path as a follow-up.
 *
 * NEVER a bootstrap/signing dependency: pure TypeScript, same as every other
 * module in this family, headless-buildable on CI/Codex. Only the Erik+Mini1
 * drill proves the real root LaunchDaemon end to end.
 */

import { createServer, type Server, type Socket } from "node:net";
import { chmod, chown, mkdir, rm } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import {
  PEER_RESOLVER_MAX_FRAME_BYTES,
  parsePeerResolveRequest,
  encodePeerResolveResponse,
  type PeerResolveResponse,
} from "./peer-resolver-protocol.js";
import { parseLsofPeer, createExecFilePeerRunner, type PeerCommandRunner } from "./peer-identity.js";

/** Root-owned parent dir for every agent's resolver socket (mirrors GATE_LIVENESS_DIR: 0711). */
export const PEER_RESOLVER_DIR = "/var/db/sanctuary/gate-peer-resolver";

/** The per-agent-uid resolver socket path. */
export function peerResolverSocketPath(agentUid: number, dir: string = PEER_RESOLVER_DIR): string {
  if (!Number.isInteger(agentUid) || agentUid <= 0) {
    throw new Error(`peer-resolver socket path requires a positive integer agent uid (got ${String(agentUid)})`);
  }
  return join(dir, `${agentUid}.sock`);
}

/** Label prefix; one resolver daemon per confined agent uid (mirrors the gate daemon's own shape). */
export const PEER_RESOLVER_DAEMON_LABEL_PREFIX = "ai.sanctuaryprotocol.egress-gate-peer-resolver";

/** The per-agent resolver daemon label. */
export function peerResolverDaemonLabel(agentUid: number): string {
  if (!Number.isInteger(agentUid) || agentUid <= 0) {
    throw new Error(`peer-resolver daemon label requires a positive integer uid (got ${String(agentUid)})`);
  }
  return `${PEER_RESOLVER_DAEMON_LABEL_PREFIX}.${agentUid}`;
}

/** The per-agent resolver daemon plist path. */
export function peerResolverDaemonPlistPath(agentUid: number): string {
  return `/Library/LaunchDaemons/${peerResolverDaemonLabel(agentUid)}.plist`;
}

/** Default hard cap on concurrent in-flight `lsof` executions inside the resolver. */
export const PEER_RESOLVER_MAX_CONCURRENT_LOOKUPS = 8;

/** Default per-lookup timeout, mirrors `PEER_LOOKUP_TIMEOUT_MS` in peer-identity.ts. */
export const PEER_RESOLVER_LOOKUP_TIMEOUT_MS = 2_000;

/** Idle-socket reap timeout (a connection that never sends a full request line). */
export const PEER_RESOLVER_IDLE_TIMEOUT_MS = 5_000;

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function assertNoControlChars(value: string, what: string): void {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(value)) {
    throw new Error(`${what} contains control characters; refusing to render plist.`);
  }
}

/** Options for {@link renderPeerResolverDaemonPlist}. */
export interface PeerResolverDaemonPlistOptions {
  /** The confined agent uid this resolver serves (names the label + the answer scope). */
  agentUid: number;
  /** Full argv of the resolver daemon entrypoint (absolute program path first). */
  programArguments: string[];
  /** Absolute fortress path, rendered as SANCTUARY_STORAGE_PATH (parity with the gate daemon plist). */
  fortressPath: string;
  /** Log directory override (default: `<fortressPath>/logs`, matching the boot daemon's own root-log convention). */
  logDir?: string;
}

/**
 * Render the resolver daemon plist. NO `UserName` key -- root, deliberately
 * (the ONE place in this family that must NOT be the gate account; the
 * privilege that used to be missing lives here, not in the gate daemon).
 * `RunAtLoad=false` + `KeepAlive={Crashed:true}`: the root supervisor
 * sequences the start inside the SAME bring-up that bootstraps the gate
 * daemon (parity with `renderEgressGateDaemonPlist`), so boot ordering stays
 * single-owner.
 */
export function renderPeerResolverDaemonPlist(options: PeerResolverDaemonPlistOptions): string {
  const label = peerResolverDaemonLabel(options.agentUid);
  if (options.programArguments.length === 0 || !isAbsolute(options.programArguments[0]!)) {
    throw new Error("peer-resolver daemon programArguments must be non-empty with an absolute program path first");
  }
  for (const arg of options.programArguments) {
    assertNoControlChars(arg, "peer-resolver daemon program argument");
  }
  if (!isAbsolute(options.fortressPath)) {
    throw new Error(`fortress path must be absolute (got ${options.fortressPath})`);
  }
  assertNoControlChars(options.fortressPath, "fortress path");
  const logDir = options.logDir ?? join(options.fortressPath, "logs");
  if (!isAbsolute(logDir)) {
    throw new Error(`peer-resolver log dir must be absolute (got ${logDir})`);
  }
  assertNoControlChars(logDir, "peer-resolver log dir");
  const stdoutPath = join(logDir, `peer-resolver-${options.agentUid}.out.log`);
  const stderrPath = join(logDir, `peer-resolver-${options.agentUid}.err.log`);
  const argsXml = options.programArguments
    .map((a) => `\t\t<string>${xmlEscape(a)}</string>`)
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${xmlEscape(label)}</string>
\t<key>ProgramArguments</key>
\t<array>
${argsXml}
\t</array>
\t<key>EnvironmentVariables</key>
\t<dict>
\t\t<key>SANCTUARY_STORAGE_PATH</key>
\t\t<string>${xmlEscape(options.fortressPath)}</string>
\t</dict>
\t<key>StandardOutPath</key>
\t<string>${xmlEscape(stdoutPath)}</string>
\t<key>StandardErrorPath</key>
\t<string>${xmlEscape(stderrPath)}</string>
\t<key>RunAtLoad</key>
\t<false/>
\t<key>KeepAlive</key>
\t<dict>
\t\t<key>Crashed</key>
\t\t<true/>
\t</dict>
</dict>
</plist>
`;
}

/** Audit/observability events the resolver daemon emits. */
export type PeerResolverEvent =
  | { kind: "listening"; agentUid: number; socketPath: string }
  | { kind: "request_denied"; agentUid: number; reason: "malformed_request" | "rate_limited" }
  | { kind: "request_resolved"; agentUid: number; clientPort: number; resolvedUid: number | null }
  | { kind: "request_faulted"; agentUid: number; clientPort: number; message: string }
  | { kind: "daemon_error"; agentUid: number; message: string };

/** Injected dependencies for {@link runPeerResolverDaemon} (host-free in tests). */
export interface PeerResolverDaemonDeps {
  /** The confined agent uid this resolver serves (the ONLY uid it will ever answer for). */
  agentUid: number;
  /** The gate service uid allowed to connect (the socket is chowned to this uid). */
  gateUid: number;
  /** The privileged command runner (default: real `lsof` via execFile; this process runs as root). */
  runner?: PeerCommandRunner;
  /** Socket parent-dir override (tests). */
  socketDir?: string;
  /** Concurrency cap override (tests). */
  maxConcurrentLookups?: number;
  /** Per-lookup timeout override (tests; passed through only when constructing the default runner). */
  lookupTimeoutMs?: number;
  /** Event sink (default: stderr lines, same convention as `gate-daemon.ts`). */
  onEvent?: (event: PeerResolverEvent) => void;
  /** Injected mkdir/chmod/chown (tests avoid touching a real root-owned path). */
  fsOps?: {
    mkdir(path: string): Promise<void>;
    chmod(path: string, mode: number): Promise<void>;
    chown(path: string, uid: number, gid: number): Promise<void>;
    rm(path: string): Promise<void>;
  };
}

/** A running resolver daemon handle. */
export interface PeerResolverDaemonHandle {
  server: Server;
  socketPath: string;
  close(): Promise<void>;
}

function realFsOps(): NonNullable<PeerResolverDaemonDeps["fsOps"]> {
  return {
    async mkdir(path: string): Promise<void> {
      await mkdir(path, { recursive: true, mode: 0o711 }).catch(() => undefined);
    },
    async chmod(path: string, mode: number): Promise<void> {
      await chmod(path, mode);
    },
    async chown(path: string, uid: number, gid: number): Promise<void> {
      await chown(path, uid, gid);
    },
    async rm(path: string): Promise<void> {
      await rm(path, { force: true });
    },
  };
}

/**
 * Handle one accepted connection: read a SINGLE bounded, newline-terminated
 * request line, resolve it (rate-limited, audited), reply once, close. Any
 * malformed input or internal fault answers a bounded `ok:false` frame (never
 * a thrown error that could crash this root process, and never a silent
 * allow-shaped answer).
 */
function handleConnection(
  socket: Socket,
  ctx: {
    agentUid: number;
    runner: PeerCommandRunner;
    onEvent: (event: PeerResolverEvent) => void;
    acquireSlot: () => boolean;
    releaseSlot: () => void;
  },
): void {
  let buffer = "";
  let handled = false;
  const respond = (resp: PeerResolveResponse): void => {
    if (handled) return;
    handled = true;
    try {
      socket.end(encodePeerResolveResponse(resp));
    } catch {
      socket.destroy();
    }
  };
  socket.setTimeout(PEER_RESOLVER_IDLE_TIMEOUT_MS, () => socket.destroy());
  socket.on("error", () => undefined);
  socket.on("data", (chunk: Buffer) => {
    if (handled) return;
    buffer += chunk.toString("utf8");
    if (Buffer.byteLength(buffer, "utf8") > PEER_RESOLVER_MAX_FRAME_BYTES) {
      ctx.onEvent({ kind: "request_denied", agentUid: ctx.agentUid, reason: "malformed_request" });
      respond({ v: 1, ok: false, reason: "malformed_request" });
      return;
    }
    const nl = buffer.indexOf("\n");
    if (nl === -1) return; // wait for the rest, bounded by the byte cap above
    const line = buffer.slice(0, nl);
    const req = parsePeerResolveRequest(line);
    if (req === null) {
      ctx.onEvent({ kind: "request_denied", agentUid: ctx.agentUid, reason: "malformed_request" });
      respond({ v: 1, ok: false, reason: "malformed_request" });
      return;
    }
    if (!ctx.acquireSlot()) {
      ctx.onEvent({ kind: "request_denied", agentUid: ctx.agentUid, reason: "rate_limited" });
      respond({ v: 1, ok: false, reason: "rate_limited" });
      return;
    }
    const selfPid = process.pid;
    void ctx.runner
      .run("lsof", ["-nP", "-Fpun", `-iTCP@127.0.0.1:${req.clientPort}`])
      .then((result) => {
        if (result.code !== 0) {
          ctx.onEvent({ kind: "request_resolved", agentUid: ctx.agentUid, clientPort: req.clientPort, resolvedUid: null });
          respond({ v: 1, ok: true, peer: null });
          return;
        }
        const peer = parseLsofPeer(result.stdout, req.clientPort, selfPid);
        ctx.onEvent({
          kind: "request_resolved",
          agentUid: ctx.agentUid,
          clientPort: req.clientPort,
          resolvedUid: peer?.uid ?? null,
        });
        respond({ v: 1, ok: true, peer });
      })
      .catch((err: unknown) => {
        ctx.onEvent({
          kind: "request_faulted",
          agentUid: ctx.agentUid,
          clientPort: req.clientPort,
          message: err instanceof Error ? err.message : String(err),
        });
        // Fail-closed: a faulted lookup answers unresolved, never a crash and
        // never a default-allow shape.
        respond({ v: 1, ok: true, peer: null });
      })
      .finally(() => ctx.releaseSlot());
  });
}

/**
 * Start the root-owned peer-resolver daemon for ONE confined agent's gate.
 * Binds the per-agent socket, applies the uid-confinement chown/chmod, then
 * serves. Host-free over injected fs ops + runner; production defaults are
 * real `mkdir`/`chown`/`chmod` and a real `lsof` execFile runner (this
 * process is root, so THAT `lsof` resolves cross-uid where the gate's own
 * could not).
 */
export async function runPeerResolverDaemon(deps: PeerResolverDaemonDeps): Promise<PeerResolverDaemonHandle> {
  if (!Number.isInteger(deps.agentUid) || deps.agentUid <= 0) {
    throw new Error(`peer-resolver daemon: agent uid must be a positive integer (got ${String(deps.agentUid)})`);
  }
  if (!Number.isInteger(deps.gateUid) || deps.gateUid <= 0) {
    throw new Error(`peer-resolver daemon: gate uid must be a positive integer (got ${String(deps.gateUid)})`);
  }
  if (deps.agentUid === deps.gateUid) {
    throw new Error("peer-resolver daemon: agent uid and gate uid must be distinct principals");
  }
  const dir = deps.socketDir ?? PEER_RESOLVER_DIR;
  const socketPath = peerResolverSocketPath(deps.agentUid, dir);
  const runner = deps.runner ?? createExecFilePeerRunner(deps.lookupTimeoutMs);
  const maxConcurrent = deps.maxConcurrentLookups ?? PEER_RESOLVER_MAX_CONCURRENT_LOOKUPS;
  const onEvent =
    deps.onEvent ??
    ((event: PeerResolverEvent): void => {
      process.stderr.write(`[egress-gate-peer-resolver] ${JSON.stringify(event)}\n`);
    });
  const fsOps = deps.fsOps ?? realFsOps();

  // Defensive dir assertion (belt-and-suspenders, mirrors liveness-oracle.ts's
  // own `writeToken`): the AUTHORITATIVE mode/ownership is asserted once by
  // `runtime-fs-plan.ts` at arming time, but a fresh boot before that plan
  // re-runs must not crash this daemon on ENOENT.
  await fsOps.mkdir(dir);
  await fsOps.chmod(dir, 0o711).catch(() => undefined);
  await fsOps.rm(socketPath); // stale socket from a prior run (EADDRINUSE otherwise)

  let activeLookups = 0;
  const acquireSlot = (): boolean => {
    if (activeLookups >= maxConcurrent) return false;
    activeLookups += 1;
    return true;
  };
  const releaseSlot = (): void => {
    activeLookups -= 1;
  };

  const server = createServer((socket) =>
    handleConnection(socket, { agentUid: deps.agentUid, runner, onEvent, acquireSlot, releaseSlot }),
  );
  server.on("error", (err) => {
    onEvent({ kind: "daemon_error", agentUid: deps.agentUid, message: err.message });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  // UID CONFINEMENT (the security-sensitive step): chmod BEFORE chown so the
  // window between bind() and the final permissions is never world-connectable
  // even transiently, then chown to the ONE gate uid this resolver serves.
  await fsOps.chmod(socketPath, 0o600);
  await fsOps.chown(socketPath, deps.gateUid, -1);

  onEvent({ kind: "listening", agentUid: deps.agentUid, socketPath });

  return {
    server,
    socketPath,
    async close(): Promise<void> {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await fsOps.rm(socketPath).catch(() => undefined);
    },
  };
}
