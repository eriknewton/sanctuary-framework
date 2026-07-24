/**
 * Tests for the gate-daemon-side privileged peer runner CLIENT (Unified
 * Protect Slice 5 S5-3 fix, 2026-07-24): the `PeerCommandRunner` shim that
 * dials the root resolver instead of shelling `lsof` locally.
 *
 * Two layers: (1) a real end-to-end round trip against the real
 * `peer-resolver-daemon.ts` server over a temp-dir UDS (proves the wire
 * format the two modules agree on), and (2) fault-injection with a fake
 * transport (connection refused, timeout, malformed response) proving every
 * failure resolves -- never rejects -- with the SAME synthetic non-zero exit
 * `exec-runner.ts` already uses, so `resolveLoopbackPeer`'s unmodified
 * `code !== 0 -> null` handling denies fail-closed by construction.
 */

import type { Socket } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createPrivilegedPeerRunner } from "../../src/egress-gate/peer-resolver-client.js";
import { runPeerResolverDaemon, type PeerResolverDaemonHandle } from "../../src/egress-gate/peer-resolver-daemon.js";
import { parseLsofPeer, resolveLoopbackPeer, type PeerCommandRunner } from "../../src/egress-gate/peer-identity.js";
import { encodePeerResolveResponse } from "../../src/egress-gate/peer-resolver-protocol.js";

const AGENT_UID = 502;
const GATE_UID = 511;
const LSOF_ARGS = (port: number): string[] => ["-nP", "-Fpun", `-iTCP@127.0.0.1:${port}`];
const GATE_PORT = 19998;

function fakeFsOps() {
  return {
    async mkdir(): Promise<void> {},
    async chmod(): Promise<void> {},
    async chown(): Promise<void> {},
    async rm(): Promise<void> {},
  };
}

describe("egress-gate/peer-resolver-client createPrivilegedPeerRunner", () => {
  it("refuses a non-positive agent uid at construction", () => {
    expect(() => createPrivilegedPeerRunner({ agentUid: 0, gatePort: GATE_PORT })).toThrow(/agent uid must be a positive integer/);
  });

  describe("scope discipline: only ever proxies the ONE expected lsof invocation shape", () => {
    it("a wrong command name resolves a synthetic failure without dialing anything", async () => {
      let dialed = false;
      const runner = createPrivilegedPeerRunner({
        agentUid: AGENT_UID,
        gatePort: GATE_PORT,
        connect: () => {
          dialed = true;
          return new EventEmitter() as unknown as Socket;
        },
      });
      const result = await runner.run("rm", ["-rf", "/"]);
      expect(result).toEqual({ code: 127, stdout: "" });
      expect(dialed).toBe(false);
    });

    it("an unexpected args shape resolves a synthetic failure without dialing anything", async () => {
      let dialed = false;
      const runner = createPrivilegedPeerRunner({
        agentUid: AGENT_UID,
        gatePort: GATE_PORT,
        connect: () => {
          dialed = true;
          return new EventEmitter() as unknown as Socket;
        },
      });
      const result = await runner.run("lsof", ["--not", "the", "expected", "shape"]);
      expect(result).toEqual({ code: 127, stdout: "" });
      expect(dialed).toBe(false);
    });
  });

  describe("fault handling: never rejects, always the synthetic non-zero exit", () => {
    it("connect() throwing synchronously resolves the synthetic failure", async () => {
      const runner = createPrivilegedPeerRunner({
        agentUid: AGENT_UID,
        gatePort: GATE_PORT,
        connect: () => {
          throw new Error("ENOENT: no such socket");
        },
      });
      await expect(runner.run("lsof", LSOF_ARGS(52344))).resolves.toEqual({ code: 127, stdout: "" });
    });

    it("a socket 'error' event resolves the synthetic failure", async () => {
      const emitter = new EventEmitter() as unknown as Socket;
      (emitter as unknown as { destroy: () => void }).destroy = () => undefined;
      const runner = createPrivilegedPeerRunner({ agentUid: AGENT_UID, gatePort: GATE_PORT, connect: () => emitter });
      const promise = runner.run("lsof", LSOF_ARGS(52344));
      emitter.emit("error", new Error("ECONNREFUSED"));
      await expect(promise).resolves.toEqual({ code: 127, stdout: "" });
    });

    it("a socket 'close' before any response resolves the synthetic failure", async () => {
      const emitter = new EventEmitter() as unknown as Socket;
      (emitter as unknown as { destroy: () => void }).destroy = () => undefined;
      const runner = createPrivilegedPeerRunner({ agentUid: AGENT_UID, gatePort: GATE_PORT, connect: () => emitter });
      const promise = runner.run("lsof", LSOF_ARGS(52344));
      emitter.emit("close");
      await expect(promise).resolves.toEqual({ code: 127, stdout: "" });
    });

    it("a TIMEOUT (no response ever arrives) resolves the synthetic failure, never hangs the caller", async () => {
      const emitter = new EventEmitter() as unknown as Socket;
      (emitter as unknown as { destroy: () => void }).destroy = () => undefined;
      const runner = createPrivilegedPeerRunner({ agentUid: AGENT_UID, gatePort: GATE_PORT, connect: () => emitter, timeoutMs: 20 });
      await expect(runner.run("lsof", LSOF_ARGS(52344))).resolves.toEqual({ code: 127, stdout: "" });
    });

    it("a MALFORMED response line resolves the synthetic failure", async () => {
      const emitter = new EventEmitter() as unknown as Socket;
      (emitter as unknown as { write: () => boolean; destroy: () => void }).write = () => true;
      (emitter as unknown as { destroy: () => void }).destroy = () => undefined;
      const runner = createPrivilegedPeerRunner({ agentUid: AGENT_UID, gatePort: GATE_PORT, connect: () => emitter });
      const promise = runner.run("lsof", LSOF_ARGS(52344));
      emitter.emit("connect");
      emitter.emit("data", Buffer.from("not json at all\n"));
      await expect(promise).resolves.toEqual({ code: 127, stdout: "" });
    });

    it("an ok:false response resolves the synthetic failure (rate-limited etc. denies, never allows)", async () => {
      const emitter = new EventEmitter() as unknown as Socket;
      (emitter as unknown as { write: () => boolean; destroy: () => void }).write = () => true;
      (emitter as unknown as { destroy: () => void }).destroy = () => undefined;
      const runner = createPrivilegedPeerRunner({ agentUid: AGENT_UID, gatePort: GATE_PORT, connect: () => emitter });
      const promise = runner.run("lsof", LSOF_ARGS(52344));
      emitter.emit("connect");
      emitter.emit("data", encodePeerResolveResponse({ v: 1, ok: false, reason: "rate_limited" }));
      await expect(promise).resolves.toEqual({ code: 127, stdout: "" });
    });
  });

  describe("synthesized stdout parses back correctly through the UNCHANGED parseLsofPeer", () => {
    it("a resolved peer synthesizes lsof-Fpun-shaped stdout that parseLsofPeer extracts identically", async () => {
      const emitter = new EventEmitter() as unknown as Socket;
      (emitter as unknown as { write: () => boolean; destroy: () => void }).write = () => true;
      (emitter as unknown as { destroy: () => void }).destroy = () => undefined;
      const runner = createPrivilegedPeerRunner({ agentUid: AGENT_UID, gatePort: GATE_PORT, connect: () => emitter });
      const promise = runner.run("lsof", LSOF_ARGS(52344));
      emitter.emit("connect");
      emitter.emit("data", encodePeerResolveResponse({ v: 1, ok: true, peer: { uid: 502, pid: 20439 } }));
      const result = await promise;
      expect(result.code).toBe(0);
      expect(parseLsofPeer(result.stdout, 52344, /* selfPid */ 1, GATE_PORT)).toEqual({ pid: 20439, uid: 502 });
    });

    it("an unresolved (peer:null) response synthesizes empty stdout, parsing to null", async () => {
      const emitter = new EventEmitter() as unknown as Socket;
      (emitter as unknown as { write: () => boolean; destroy: () => void }).write = () => true;
      (emitter as unknown as { destroy: () => void }).destroy = () => undefined;
      const runner = createPrivilegedPeerRunner({ agentUid: AGENT_UID, gatePort: GATE_PORT, connect: () => emitter });
      const promise = runner.run("lsof", LSOF_ARGS(52344));
      emitter.emit("connect");
      emitter.emit("data", encodePeerResolveResponse({ v: 1, ok: true, peer: null }));
      const result = await promise;
      expect(result).toEqual({ code: 0, stdout: "" });
      expect(parseLsofPeer(result.stdout, 52344, 1, GATE_PORT)).toBeNull();
    });
  });
});

describe("egress-gate/peer-resolver-client + peer-resolver-daemon: real end-to-end UDS round trip", () => {
  let socketDir: string;
  let handle: PeerResolverDaemonHandle;

  beforeEach(async () => {
    socketDir = await mkdtemp(join(tmpdir(), "peer-resolver-client-e2e-"));
  });

  afterEach(async () => {
    await handle?.close();
    await rm(socketDir, { recursive: true, force: true });
  });

  it("a real resolver daemon (simulated root-lsof) answers through the client, and resolveLoopbackPeer (UNCHANGED) parses it correctly", async () => {
    const rootRunner: PeerCommandRunner = {
      run: (_c, args) => {
        const port = Number(/:(\d+)$/.exec(args[2] ?? "")?.[1] ?? 0);
        return Promise.resolve({
          code: 0,
          stdout: ["p20439", "u502", `n127.0.0.1:${port}->127.0.0.1:19998`, ""].join("\n"),
        });
      },
    };
    handle = await runPeerResolverDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      gatePort: GATE_PORT,
      socketDir,
      runner: rootRunner,
      fsOps: fakeFsOps(),
      onEvent: () => undefined,
    });
    const clientRunner = createPrivilegedPeerRunner({ agentUid: AGENT_UID, gatePort: GATE_PORT, socketPath: handle.socketPath });
    // The EXACT same call `peer-identity.ts`'s resolveLoopbackPeer makes, unmodified.
    const peer = await resolveLoopbackPeer({ clientPort: 52344, gatePort: GATE_PORT, selfPid: 1, runner: clientRunner });
    expect(peer).toEqual({ pid: 20439, uid: 502 });
  });

  it("resolver daemon unreachable (never started): the client's transport failure denies fail-closed, never throws", async () => {
    const clientRunner = createPrivilegedPeerRunner({
      agentUid: AGENT_UID,
      gatePort: GATE_PORT,
      socketPath: join(socketDir, "999.sock"), // nothing listening here
    });
    const peer = await resolveLoopbackPeer({ clientPort: 52344, gatePort: GATE_PORT, selfPid: 1, runner: clientRunner });
    expect(peer).toBeNull();
  });
});
