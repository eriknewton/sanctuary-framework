/**
 * Tests for the privileged peer-resolver DAEMON (Unified Protect Slice 5
 * S5-3 fix, 2026-07-24): the label/plist renderer's refusal set, the
 * uid-confinement chmod/chown sequence, request handling (resolve, deny
 * malformed, rate-limit), and the fault path (a faulting runner answers
 * unresolved, never a crash). All host-free: a real loopback UDS in a temp
 * dir, an injected `PeerCommandRunner`, and injected fs ops for the
 * production dir/socket path (no real root needed).
 */

import { createConnection } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { stat } from "node:fs/promises";
import {
  PEER_RESOLVER_DAEMON_LABEL_PREFIX,
  PEER_RESOLVER_SOCKET_UMASK,
  peerResolverDaemonLabel,
  peerResolverDaemonPlistPath,
  peerResolverSocketPath,
  renderPeerResolverDaemonPlist,
  runPeerResolverDaemon,
  type PeerResolverEvent,
} from "../../src/egress-gate/peer-resolver-daemon.js";
import type { PeerCommandRunner } from "../../src/egress-gate/peer-identity.js";
import {
  encodePeerResolveRequest,
  parsePeerResolveResponse,
} from "../../src/egress-gate/peer-resolver-protocol.js";

const AGENT_UID = 502;
const GATE_UID = 511;
const GATE_PORT = 19998;

describe("egress-gate/peer-resolver-daemon paths + label", () => {
  it("label/plist/socket paths are uid-keyed and refuse non-positive uids", () => {
    expect(peerResolverDaemonLabel(AGENT_UID)).toBe(`${PEER_RESOLVER_DAEMON_LABEL_PREFIX}.502`);
    expect(peerResolverDaemonPlistPath(AGENT_UID)).toBe(
      `/Library/LaunchDaemons/${PEER_RESOLVER_DAEMON_LABEL_PREFIX}.502.plist`,
    );
    expect(peerResolverSocketPath(AGENT_UID, "/tmp/x")).toBe("/tmp/x/502.sock");
    expect(() => peerResolverDaemonLabel(0)).toThrow(/positive integer uid/);
    expect(() => peerResolverSocketPath(-1)).toThrow(/positive integer agent uid/);
  });

  it("the resolver label is DISTINCT from the gate daemon label (never colliding LaunchDaemons)", () => {
    expect(peerResolverDaemonLabel(AGENT_UID)).not.toBe(`ai.sanctuaryprotocol.egress-gate.${AGENT_UID}`);
  });
});

describe("egress-gate/peer-resolver-daemon renderPeerResolverDaemonPlist", () => {
  const base = {
    agentUid: AGENT_UID,
    programArguments: ["/usr/local/bin/sanctuary", "castle-wall", "peer-resolver-daemon", "--agent-uid=502", "--gate-uid=511"],
    fortressPath: "/Users/operator/.sanctuary",
  };

  it("renders NO UserName key (root), RunAtLoad=false, and Crashed-only KeepAlive", () => {
    const plist = renderPeerResolverDaemonPlist(base);
    expect(plist).not.toContain("<key>UserName</key>");
    expect(plist).toContain("<key>RunAtLoad</key>\n\t<false/>");
    expect(plist).toContain("<key>Crashed</key>");
    expect(plist).toContain(`${PEER_RESOLVER_DAEMON_LABEL_PREFIX}.502`);
  });

  it("derives stdout/stderr under <fortressPath>/logs by default", () => {
    const plist = renderPeerResolverDaemonPlist(base);
    expect(plist).toContain("/Users/operator/.sanctuary/logs/peer-resolver-502.out.log");
    expect(plist).toContain("/Users/operator/.sanctuary/logs/peer-resolver-502.err.log");
  });

  it("refuses empty/relative programArguments", () => {
    expect(() => renderPeerResolverDaemonPlist({ ...base, programArguments: [] })).toThrow(/non-empty/);
    expect(() => renderPeerResolverDaemonPlist({ ...base, programArguments: ["relative/bin"] })).toThrow(/non-empty/);
  });

  it("refuses a relative fortress path", () => {
    expect(() => renderPeerResolverDaemonPlist({ ...base, fortressPath: "relative/path" })).toThrow(/absolute/);
  });

  it("refuses control characters in any rendered field", () => {
    expect(() =>
      renderPeerResolverDaemonPlist({ ...base, programArguments: [...base.programArguments, "evil\x00arg"] }),
    ).toThrow(/control characters/);
  });

  it("XML-escapes special characters in the fortress path", () => {
    const plist = renderPeerResolverDaemonPlist({ ...base, fortressPath: "/Users/o&p<e>r/.sanctuary" });
    expect(plist).toContain("/Users/o&amp;p&lt;e&gt;r/.sanctuary");
  });

  it("renders a Umask key (fix-round HIGH, defense-in-depth): the DECIMAL value of octal 0o077 (63), never the ambient default", () => {
    const plist = renderPeerResolverDaemonPlist(base);
    expect(plist).toContain("<key>Umask</key>\n\t<integer>63</integer>");
    expect(PEER_RESOLVER_SOCKET_UMASK).toBe(0o077);
    expect(PEER_RESOLVER_SOCKET_UMASK).toBe(63);
  });
});

/** A PeerCommandRunner double that records every invocation and returns scripted lsof output. */
function scriptedRunner(script: (args: readonly string[]) => { code: number; stdout: string }): PeerCommandRunner & {
  calls: string[][];
} {
  const calls: string[][] = [];
  return {
    calls,
    run: (command, args) => {
      calls.push([command, ...args]);
      return Promise.resolve(script(args));
    },
  };
}

/** Realistic lsof -Fpun output resolving clientPort to (pid, uid). */
function lsofResolving(clientPort: number, pid: number, uid: number): string {
  return [`p${pid}`, `u${uid}`, `n127.0.0.1:${clientPort}->127.0.0.1:19998`, ""].join("\n");
}

describe("egress-gate/peer-resolver-daemon runPeerResolverDaemon (real UDS, host-free fs ops)", () => {
  let socketDir: string;
  const events: PeerResolverEvent[] = [];
  const fsCalls: string[] = [];

  beforeEach(async () => {
    socketDir = await mkdtemp(join(tmpdir(), "peer-resolver-test-"));
    events.length = 0;
    fsCalls.length = 0;
  });

  afterEach(async () => {
    await rm(socketDir, { recursive: true, force: true });
  });

  function fakeFsOps() {
    return {
      async mkdir(path: string): Promise<void> {
        fsCalls.push(`mkdir ${path}`);
      },
      async chmod(path: string, mode: number): Promise<void> {
        fsCalls.push(`chmod ${path} 0o${mode.toString(8)}`);
      },
      async chown(path: string, uid: number, gid: number): Promise<void> {
        fsCalls.push(`chown ${path} ${uid}:${gid}`);
      },
      async rm(path: string): Promise<void> {
        fsCalls.push(`rm ${path}`);
      },
    };
  }

  async function rawRequest(socketPath: string, clientPort: number): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const socket = createConnection(socketPath);
      let buffer = "";
      socket.on("connect", () => socket.write(encodePeerResolveRequest({ v: 2, clientPort })));
      socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        const nl = buffer.indexOf("\n");
        if (nl !== -1) {
          resolve(parsePeerResolveResponse(buffer.slice(0, nl)));
          socket.end();
        }
      });
      socket.on("error", reject);
      setTimeout(() => reject(new Error("test request timeout")), 3000).unref();
    });
  }

  it("REFUSES non-positive/equal agent/gate uids at construction", async () => {
    await expect(
      runPeerResolverDaemon({ agentUid: 0, gateUid: GATE_UID, gatePort: GATE_PORT, socketDir }),
    ).rejects.toThrow(/agent uid must be a positive integer/);
    await expect(
      runPeerResolverDaemon({ agentUid: AGENT_UID, gateUid: -1, gatePort: GATE_PORT, socketDir }),
    ).rejects.toThrow(/gate uid must be a positive integer/);
    await expect(
      runPeerResolverDaemon({ agentUid: 502, gateUid: 502, gatePort: GATE_PORT, socketDir }),
    ).rejects.toThrow(/distinct principals/);
  });

  it("REFUSES an invalid gate port at construction (fix-round BLOCKER: gatePort is REQUIRED, never optional)", async () => {
    await expect(
      runPeerResolverDaemon({ agentUid: AGENT_UID, gateUid: GATE_UID, gatePort: 0, socketDir }),
    ).rejects.toThrow(/gate port must be a valid TCP port/);
    await expect(
      runPeerResolverDaemon({ agentUid: AGENT_UID, gateUid: GATE_UID, gatePort: 70000, socketDir }),
    ).rejects.toThrow(/gate port must be a valid TCP port/);
    await expect(
      runPeerResolverDaemon({
        agentUid: AGENT_UID,
        gateUid: GATE_UID,
        gatePort: undefined as unknown as number,
        socketDir,
      }),
    ).rejects.toThrow(/gate port must be a valid TCP port/);
  });

  it("binds the per-agent socket, applies chmod 0600 THEN chown to the gate uid (uid confinement), and listening is audited", async () => {
    const handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      fsOps: fakeFsOps(),
      onEvent: (e) => events.push(e),
    });
    try {
      expect(handle.socketPath).toBe(join(socketDir, "502.sock"));
      // chmod BEFORE chown (never a window where the socket is world-connectable
      // under a permissive umask before the owner-narrowing chown lands).
      const chmodIdx = fsCalls.indexOf(`chmod ${handle.socketPath} 0o600`);
      const chownIdx = fsCalls.indexOf(`chown ${handle.socketPath} ${GATE_UID}:-1`);
      expect(chmodIdx).toBeGreaterThanOrEqual(0);
      expect(chownIdx).toBeGreaterThan(chmodIdx);
      expect(events.some((e) => e.kind === "listening" && e.agentUid === AGENT_UID)).toBe(true);
    } finally {
      await handle.close();
    }
  });

  it("resolves a valid request through the injected (simulated root-lsof) runner and audits the outcome", async () => {
    const runner = scriptedRunner((args) => {
      const port = Number(/:(\d+)$/.exec(args[2] ?? "")?.[1] ?? 0);
      return { code: 0, stdout: lsofResolving(port, 20439, AGENT_UID) };
    });
    const handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      runner,
      fsOps: fakeFsOps(),
      onEvent: (e) => events.push(e),
    });
    try {
      const resp = await rawRequest(handle.socketPath, 52344);
      expect(resp).toEqual({ v: 2, ok: true, peer: { uid: AGENT_UID, pid: 20439 }, gatePort: GATE_PORT });
      expect(runner.calls[0]).toEqual(["lsof", "-nP", "-Fpun", "-iTCP@127.0.0.1:52344"]);
      const resolved = events.find((e) => e.kind === "request_resolved");
      expect(resolved).toMatchObject({ kind: "request_resolved", clientPort: 52344, resolvedUid: AGENT_UID });
    } finally {
      await handle.close();
    }
  });

  it("answers unresolved (peer: null) when the runner exits non-zero (mirrors resolveLoopbackPeer's own contract)", async () => {
    const runner = scriptedRunner(() => ({ code: 1, stdout: "" }));
    const handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      runner,
      fsOps: fakeFsOps(),
      onEvent: () => undefined,
    });
    try {
      const resp = await rawRequest(handle.socketPath, 52344);
      expect(resp).toEqual({ v: 2, ok: true, peer: null, gatePort: GATE_PORT });
    } finally {
      await handle.close();
    }
  });

  it("FAULT: a THROWING runner answers unresolved, never crashes the daemon and never a default-allow shape", async () => {
    const runner: PeerCommandRunner = { run: () => Promise.reject(new Error("lsof: command not found")) };
    const handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      runner,
      fsOps: fakeFsOps(),
      onEvent: (e) => events.push(e),
    });
    try {
      const resp = await rawRequest(handle.socketPath, 52344);
      expect(resp).toEqual({ v: 2, ok: true, peer: null, gatePort: GATE_PORT });
      expect(events.some((e) => e.kind === "request_faulted")).toBe(true);
      // The daemon is still alive and serves the NEXT request normally.
      const second = await rawRequest(handle.socketPath, 52345);
      expect(second).toEqual({ v: 2, ok: true, peer: null, gatePort: GATE_PORT });
    } finally {
      await handle.close();
    }
  });

  it("DENIES a malformed request line (audited) instead of throwing", async () => {
    const handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      fsOps: fakeFsOps(),
      onEvent: (e) => events.push(e),
    });
    try {
      const resp = await new Promise((resolve, reject) => {
        const socket = createConnection(handle.socketPath);
        let buffer = "";
        socket.on("connect", () => socket.write('{"v":2,"clientPort":"not-a-port"}\n'));
        socket.on("data", (chunk) => {
          buffer += chunk.toString("utf8");
          const nl = buffer.indexOf("\n");
          if (nl !== -1) {
            resolve(parsePeerResolveResponse(buffer.slice(0, nl)));
            socket.end();
          }
        });
        socket.on("error", reject);
        setTimeout(() => reject(new Error("timeout")), 3000).unref();
      });
      expect(resp).toEqual({ v: 2, ok: false, reason: "malformed_request" });
      expect(events.some((e) => e.kind === "request_denied" && e.reason === "malformed_request")).toBe(true);
    } finally {
      await handle.close();
    }
  });

  it("RATE-LIMITS: over the concurrency cap, extra in-flight requests are denied rate_limited, never queued forever", async () => {
    const releasers: Array<() => void> = [];
    const runner: PeerCommandRunner = {
      run: () =>
        new Promise((resolve) => {
          releasers.push(() => resolve({ code: 0, stdout: "" }));
        }),
    };
    const handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      runner,
      maxConcurrentLookups: 2,
      fsOps: fakeFsOps(),
      onEvent: (e) => events.push(e),
    });
    try {
      const p1 = rawRequest(handle.socketPath, 1001);
      const p2 = rawRequest(handle.socketPath, 1002);
      const p3 = rawRequest(handle.socketPath, 1003); // over the cap of 2
      await new Promise((r) => setTimeout(r, 50));
      const third = await p3;
      expect(third).toEqual({ v: 2, ok: false, reason: "rate_limited" });
      // Release the two held lookups so the daemon can close cleanly.
      for (const release of releasers.splice(0)) release();
      expect(await p1).toEqual({ v: 2, ok: true, peer: null, gatePort: GATE_PORT });
      expect(await p2).toEqual({ v: 2, ok: true, peer: null, gatePort: GATE_PORT });
      expect(events.some((e) => e.kind === "request_denied" && e.reason === "rate_limited")).toBe(true);
    } finally {
      await handle.close();
    }
  });

  it("close() removes the socket file", async () => {
    const handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      fsOps: fakeFsOps(),
      onEvent: () => undefined,
    });
    const socketPath = handle.socketPath;
    await handle.close();
    await expect(rawRequest(socketPath, 1)).rejects.toThrow();
  });

  it("BLOCKER regression (fix-round 2026-07-24, fail-before/pass-after): a same-local-port/DIFFERENT-remote decoy record for the AGENT, listed BEFORE the real non-agent gate-port record, does NOT get matched -- the daemon resolves the OPERATOR, not the agent", async () => {
    // Pre-fix `parseLsofPeer(output, clientPort, selfPid)` matched the FIRST
    // record whose LOCAL endpoint started `127.0.0.1:<clientPort>->`,
    // ignoring the remote entirely. With SO_REUSEADDR two loopback sockets
    // can share one local port with different remotes; this real root `lsof`
    // dump lists the AGENT's own decoy socket (same local port, WRONG
    // remote) FIRST, then the actual gate connection from the OPERATOR uid.
    // Pre-fix this daemon would have answered {uid: AGENT_UID} -- a
    // wrong-ALLOW upstream at `decideGateClientAuth`. Post-fix, the full
    // 4-tuple match (this daemon's OWN `deps.gatePort`, never the wire
    // request) skips the decoy and resolves the OPERATOR, which the gate
    // correctly denies `peer_uid_mismatch`.
    const OPERATOR_UID = 501;
    const OPERATOR_PID = 30000;
    const runner = scriptedRunner((args) => {
      const port = Number(/:(\d+)$/.exec(args[2] ?? "")?.[1] ?? 0);
      const decoyThenReal = [
        `p99999`,
        `u${AGENT_UID}`,
        `n127.0.0.1:${port}->127.0.0.1:9999`, // decoy: agent-owned, WRONG remote
        `p${OPERATOR_PID}`,
        `u${OPERATOR_UID}`,
        `n127.0.0.1:${port}->127.0.0.1:${GATE_PORT}`, // the real gate connection
        "",
      ].join("\n");
      return { code: 0, stdout: decoyThenReal };
    });
    const handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      runner,
      fsOps: fakeFsOps(),
      onEvent: (e) => events.push(e),
    });
    try {
      const resp = await rawRequest(handle.socketPath, 52344);
      expect(resp).toEqual({ v: 2, ok: true, peer: { uid: OPERATOR_UID, pid: OPERATOR_PID }, gatePort: GATE_PORT });
      // Never the agent -- the wrong-ALLOW this regression exists to prove closed.
      expect((resp as { peer: { uid: number } }).peer.uid).not.toBe(AGENT_UID);
      const resolved = events.find((e) => e.kind === "request_resolved");
      expect(resolved).toMatchObject({ kind: "request_resolved", clientPort: 52344, resolvedUid: OPERATOR_UID });
    } finally {
      await handle.close();
    }
  });

  it("HIGH regression: under an ambient umask(0), the resolver socket is NEVER world-writable even in the window before the explicit chmod(0600)", async () => {
    const priorUmask = process.umask(0);
    let observedModeBeforeChmod: number | null = null;
    const fsCalls2: string[] = [];
    const fsOps = {
      async mkdir(path: string): Promise<void> {
        fsCalls2.push(`mkdir ${path}`);
      },
      async chmod(path: string, mode: number): Promise<void> {
        // Observe the REAL on-disk mode `server.listen()` produced, BEFORE
        // this chmod call changes it -- proves what umask was actually in
        // effect at bind() time, not merely that the later chmod ran.
        const st = await stat(path);
        observedModeBeforeChmod = st.mode & 0o777;
        fsCalls2.push(`chmod ${path} 0o${mode.toString(8)}`);
      },
      async chown(): Promise<void> {
        // A real chown needs root; this fix is about the socket's CREATED
        // mode, not the ownership step, so it is a no-op here.
        fsCalls2.push("chown (skipped, no root in CI)");
      },
      async rm(path: string): Promise<void> {
        fsCalls2.push(`rm ${path}`);
      },
    };
    try {
      const handle = await runPeerResolverDaemon({
        agentUid: AGENT_UID,
        gateUid: GATE_UID,
        gatePort: GATE_PORT,
        socketDir,
        fsOps,
        onEvent: (e) => events.push(e),
      });
      try {
        expect(observedModeBeforeChmod).not.toBeNull();
        // No group/other bits, even though the test's ambient umask was 0
        // (maximally permissive): the daemon's own process.umask(0o077)
        // around listen() is what actually restricted socket creation.
        expect((observedModeBeforeChmod as number) & 0o077).toBe(0);
      } finally {
        await handle.close();
      }
      // The daemon must restore the CALLER's prior umask once the socket
      // exists -- it must not leave the process narrower than it found it.
      expect(process.umask()).toBe(0);
    } finally {
      process.umask(priorUmask);
    }
  });

  it("LOW regression: pipelined extra request lines on ONE connection dispatch only ONE root lsof, not one per line", async () => {
    let dispatches = 0;
    const releasers: Array<() => void> = [];
    const runner: PeerCommandRunner = {
      run: () =>
        new Promise((resolve) => {
          dispatches += 1;
          releasers.push(() => resolve({ code: 0, stdout: "" }));
        }),
    };
    const handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      runner,
      fsOps: fakeFsOps(),
      onEvent: (e) => events.push(e),
    });
    try {
      const responsePromise = new Promise<unknown>((resolve, reject) => {
        const socket = createConnection(handle.socketPath);
        let buffer = "";
        socket.on("connect", () => {
          // Pipeline FIVE request lines on the SAME connection before the
          // (held-open) first lookup ever resolves. Pre-fix, `handled` was
          // only set inside `respond()`, so each of these re-entered the
          // data handler and dispatched its OWN root lsof while the first
          // was still in flight -- one connection consuming five lookup
          // slots. Post-fix, `requestAccepted` is set the instant the FIRST
          // line parses, so lines 2-5 are silently dropped.
          for (let i = 0; i < 5; i++) {
            socket.write(encodePeerResolveRequest({ v: 2, clientPort: 1000 + i }));
          }
        });
        socket.on("data", (chunk) => {
          buffer += chunk.toString("utf8");
          const nl = buffer.indexOf("\n");
          if (nl !== -1) {
            resolve(parsePeerResolveResponse(buffer.slice(0, nl)));
            socket.end();
          }
        });
        socket.on("error", reject);
        setTimeout(() => reject(new Error("test request timeout")), 3000).unref();
      });
      // Give any (incorrect, pre-fix-shaped) extra dispatches a chance to
      // have fired BEFORE releasing the held lookup(s).
      await new Promise((r) => setTimeout(r, 50));
      expect(dispatches).toBe(1);
      for (const release of releasers.splice(0)) release();
      expect(await responsePromise).toEqual({ v: 2, ok: true, peer: null, gatePort: GATE_PORT });
    } finally {
      await handle.close();
    }
  });
});
