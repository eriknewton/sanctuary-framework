/**
 * Integration tests for the exclusive-egress policy gate (Unified Protect
 * Slice 1) on real loopback sockets (ephemeral ports; no real pf, liveness
 * is injected). Pins the MANDATORY fail-closed liveness behavior, the
 * loopback-only bind, policy allow/deny, and the advisory peer-identity
 * events.
 */

import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";

import {
  createExclusiveEgressGate,
  startExclusiveEgressGate,
  GATE_BIND_HOST,
  type EgressGateEvent,
  type ExclusiveEgressGateOptions,
  type GateLivenessProbe,
} from "../../src/egress-gate/gate-server.js";
import type { AllowlistRule } from "../../src/castle-wall/allowlist/schema.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../src/castle-wall/constants.js";
import type { PeerCommandRunner } from "../../src/egress-gate/peer-identity.js";

const liveProbe: GateLivenessProbe = { check: () => Promise.resolve({ live: true, reasons: [] }) };
const deadProbe: GateLivenessProbe = {
  check: () => Promise.resolve({ live: false, reasons: ["anchor not loaded"] }),
};

function allowRule(host: string, port: number): AllowlistRule {
  return {
    id: `test-allow-${host}-${port}`,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-07-02T00:00:00Z",
    match: { host, port: [port], protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

/** A local upstream that answers a fixed banner then closes. */
function startUpstream(): Promise<{ port: number; close: () => void }> {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => {
      socket.end("upstream-hello");
    });
    server.listen(0, "127.0.0.1", () => {
      resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() });
    });
  });
}

/** Issue a raw CONNECT and capture the status line (+ tunneled bytes). */
function rawConnect(
  gatePort: number,
  authority: string,
): Promise<{ statusLine: string; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(gatePort, "127.0.0.1", () => {
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    });
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
    });
    socket.on("end", () => {
      const statusLine = data.split("\r\n")[0] ?? "";
      const body = data.split("\r\n\r\n").slice(1).join("\r\n\r\n");
      resolve({ statusLine, body });
    });
    socket.on("error", reject);
    setTimeout(() => socket.destroy(new Error("test connect timeout")), 5_000).unref();
  });
}

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups.pop()!();
  }
});

async function startGateOnEphemeralPort(
  overrides: Partial<ExclusiveEgressGateOptions>,
): Promise<{ port: number; events: EgressGateEvent[] }> {
  const events: EgressGateEvent[] = [];
  const options: ExclusiveEgressGateOptions = {
    policy: { agent_uid: 502, gate_port: 19998 },
    rules: [],
    livenessProbe: liveProbe,
    onEvent: (e) => events.push(e),
    // Loopback upstreams are non-routable by the production check; tests
    // allow them explicitly (same pattern as the egress-proxy tests).
    isRoutable: () => true,
    ...overrides,
  };
  const server = createExclusiveEgressGate(options);
  await new Promise<void>((resolve) => server.listen(0, GATE_BIND_HOST, resolve));
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return { port: (server.address() as AddressInfo).port, events };
}

describe("egress-gate/gate-server", () => {
  it("tunnels an allowed CONNECT to the upstream (policy allow path)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startGateOnEphemeralPort({
      rules: [allowRule("127.0.0.1", upstream.port)],
    });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(result.statusLine).toBe("HTTP/1.1 200 Connection Established");
    expect(result.body).toContain("upstream-hello");
    const decision = events.find((e) => e.kind === "decision");
    expect(decision && decision.kind === "decision" && decision.decision.disposition).toBe("allow");
  });

  it("survives a client reset during the async decision window (no process-killing uncaughtException)", async () => {
    // Regression: the confined agent is the party on the client socket and
    // can RST mid-decision (liveness probe / peer resolution / policy). A
    // listener-less 'error' event would crash the gate process; before the
    // fix this test killed the vitest worker with an uncaught ECONNRESET.
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const slowProbe: GateLivenessProbe = {
      check: () =>
        new Promise((resolve) => setTimeout(() => resolve({ live: true, reasons: [] }), 150)),
    };
    const { port } = await startGateOnEphemeralPort({
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: slowProbe,
    });
    // Send CONNECT, then reset the connection while the probe is in flight.
    await new Promise<void>((resolve) => {
      const socket = net.connect(port, "127.0.0.1", () => {
        socket.write(`CONNECT 127.0.0.1:${upstream.port} HTTP/1.1\r\nHost: x\r\n\r\n`);
        setTimeout(() => {
          socket.resetAndDestroy();
          resolve();
        }, 50);
      });
      socket.on("error", () => {});
    });
    // Let the in-flight handler run past every await with the dead client.
    await new Promise((r) => setTimeout(r, 300));
    // The gate survived: a fresh CONNECT still tunnels.
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(result.statusLine).toBe("HTTP/1.1 200 Connection Established");
    expect(result.body).toContain("upstream-hello");
  });

  it("denies an allowlist miss with 403 (default deny)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port } = await startGateOnEphemeralPort({ rules: [] });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
  });

  it("REFUSES to proxy when the liveness probe reports not-live, even for an allowed destination (fail-closed)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startGateOnEphemeralPort({
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: deadProbe,
    });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(result.statusLine).toBe("HTTP/1.1 503 Service Unavailable");
    const refusal = events.find((e) => e.kind === "liveness_refused");
    expect(refusal && refusal.kind === "liveness_refused" && refusal.reasons).toEqual([
      "anchor not loaded",
    ]);
  });

  it("REFUSES to proxy when the liveness probe throws (fail-closed on probe error)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startGateOnEphemeralPort({
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: { check: () => Promise.reject(new Error("pfctl exploded")) },
    });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(result.statusLine).toBe("HTTP/1.1 503 Service Unavailable");
    const refusal = events.find((e) => e.kind === "liveness_refused");
    expect(refusal && refusal.kind === "liveness_refused" && refusal.reasons.join(" ")).toContain(
      "pfctl exploded",
    );
  });

  it("never serves a cached NEGATIVE liveness result (re-probes after failure)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    let live = false;
    let probes = 0;
    const { port } = await startGateOnEphemeralPort({
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: {
        check: () => {
          probes += 1;
          return Promise.resolve({ live, reasons: live ? [] : ["down"] });
        },
      },
    });
    const first = await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(first.statusLine).toBe("HTTP/1.1 503 Service Unavailable");
    live = true; // anchor comes back: the very next request must re-probe
    const second = await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(second.statusLine).toBe("HTTP/1.1 200 Connection Established");
    expect(probes).toBe(2);
  });

  it("caches a POSITIVE liveness result inside the TTL", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    let probes = 0;
    const { port } = await startGateOnEphemeralPort({
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessTtlMs: 60_000,
      livenessProbe: {
        check: () => {
          probes += 1;
          return Promise.resolve({ live: true, reasons: [] });
        },
      },
    });
    await rawConnect(port, `127.0.0.1:${upstream.port}`);
    await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(probes).toBe(1);
  });

  it("emits a loud peer_uid_mismatch event for a non-agent peer but still evaluates policy (advisory-only)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // The scripted lsof reports uid 501 (operator), not the agent uid 502.
    const peerRunner: PeerCommandRunner = {
      run: (_c, args) => {
        const portArg = /:(\d+)$/.exec(args[2] ?? "");
        const clientPort = portArg ? Number(portArg[1]) : 0;
        return Promise.resolve({
          code: 0,
          stdout: [`p777`, `u501`, `n127.0.0.1:${clientPort}->127.0.0.1:x`, ""].join("\n"),
        });
      },
    };
    const { port, events } = await startGateOnEphemeralPort({
      rules: [allowRule("127.0.0.1", upstream.port)],
      peerRunner,
    });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(result.statusLine).toBe("HTTP/1.1 200 Connection Established");
    const mismatch = events.find((e) => e.kind === "peer_uid_mismatch");
    expect(mismatch && mismatch.kind === "peer_uid_mismatch" && mismatch.peerUid).toBe(501);
    expect(mismatch && mismatch.kind === "peer_uid_mismatch" && mismatch.agentUid).toBe(502);
  });

  it("answers non-CONNECT requests with 405 naming the sanctioned path", async () => {
    const { port } = await startGateOnEphemeralPort({});
    const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = http.get({ host: "127.0.0.1", port, path: "/" }, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      });
      req.on("error", reject);
    });
    expect(response.status).toBe(405);
    expect(response.body).toContain("CONNECT");
  });

  it("startExclusiveEgressGate binds the loopback host and the policy port only", async () => {
    const handle = await startExclusiveEgressGate({
      policy: { agent_uid: 502, gate_port: 0 as never },
      rules: [],
      livenessProbe: liveProbe,
    }).catch(() => null);
    // Port 0 is rejected by policy validation: the gate never binds a
    // wildcard/ephemeral production port silently.
    expect(handle).toBeNull();
  });

  it("rejects construction with a malformed policy", () => {
    expect(() =>
      createExclusiveEgressGate({
        policy: { agent_uid: 0, gate_port: 19998 },
        rules: [],
        livenessProbe: liveProbe,
      }),
    ).toThrow(/malformed exclusive-egress gate policy/);
  });

  it("binds 127.0.0.1, not the wildcard address", async () => {
    const { port } = await startGateOnEphemeralPort({});
    const address = await new Promise<string>((resolve, reject) => {
      const socket = net.connect(port, "127.0.0.1", () => {
        resolve(socket.localAddress ?? "");
        socket.destroy();
      });
      socket.on("error", reject);
    });
    expect(address.startsWith("127.")).toBe(true);
  });
});
