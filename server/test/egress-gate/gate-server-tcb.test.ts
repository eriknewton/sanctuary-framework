/**
 * Integration tests for the gate's FAIL-CLOSED client authorization (Slice 5
 * S5-3) on real loopback sockets. Anonymous / wrong-uid / unresolved-peer /
 * stale-generation clients are DENIED (403 + client_denied); a valid credential
 * from the matching peer tunnels. Also proves the oracle-liveness composition:
 * an invalidated (flushed) liveness token denies on the next CONNECT.
 */

import { describe, it, expect, afterEach } from "vitest";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { createHash, generateKeyPairSync } from "node:crypto";

import {
  createExclusiveEgressGate,
  GATE_BIND_HOST,
  type EgressGateEvent,
  type ExclusiveEgressGateOptions,
  type GateLivenessProbe,
} from "../../src/egress-gate/gate-server.js";
import { createGateClientAuthenticator } from "../../src/egress-gate/gate-client-auth.js";
import {
  formatGateCredentialHeader,
  GATE_CREDENTIAL_VERSION,
  type GateAcceptSource,
  type GateCredentialAcceptRecord,
} from "../../src/egress-gate/gate-credential.js";
import {
  GateLivenessOracle,
  createOracleLivenessProbe,
  type LivenessOracleOps,
  type LivenessTokenSource,
} from "../../src/egress-gate/liveness-oracle.js";
import type { PeerCommandRunner } from "../../src/egress-gate/peer-identity.js";
import type { AllowlistRule } from "../../src/castle-wall/allowlist/schema.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../src/castle-wall/constants.js";
import type { PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";

const AGENT_UID = 502;
const GEN = 7;
const SECRET = "deadbeefcafef00d";

function sha256Hex(v: string): string {
  return createHash("sha256").update(v, "utf8").digest("hex");
}

const liveProbe: GateLivenessProbe = { check: () => Promise.resolve({ live: true, reasons: [] }) };

const acceptRecord: GateCredentialAcceptRecord = {
  version: GATE_CREDENTIAL_VERSION,
  generation_id: GEN,
  secret_sha256: sha256Hex(SECRET),
};
const acceptSource: GateAcceptSource = { current: () => Promise.resolve(acceptRecord) };

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

/** A peerRunner that reports a fixed uid for the connecting client port. */
function peerRunnerReporting(uid: number): PeerCommandRunner {
  return {
    run: (_c, args) => {
      const portArg = /:(\d+)$/.exec(args[2] ?? "");
      const clientPort = portArg ? Number(portArg[1]) : 0;
      return Promise.resolve({
        code: 0,
        stdout: [`p999`, `u${uid}`, `n127.0.0.1:${clientPort}->127.0.0.1:x`, ""].join("\n"),
      });
    },
  };
}

/** A peerRunner that never resolves the client (empty lsof output). */
const peerRunnerUnresolving: PeerCommandRunner = {
  run: () => Promise.resolve({ code: 0, stdout: "" }),
};

function startUpstream(): Promise<{ port: number; close: () => void }> {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => socket.end("upstream-hello"));
    server.listen(0, "127.0.0.1", () => {
      resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() });
    });
  });
}

/** CONNECT with an optional Proxy-Authorization header; capture status + body. */
function rawConnect(
  gatePort: number,
  authority: string,
  proxyAuth?: string,
): Promise<{ statusLine: string; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(gatePort, "127.0.0.1", () => {
      const authLine = proxyAuth ? `Proxy-Authorization: ${proxyAuth}\r\n` : "";
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${authLine}\r\n`);
    });
    let data = "";
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
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

async function startTcbGate(
  overrides: Partial<ExclusiveEgressGateOptions>,
): Promise<{ port: number; events: EgressGateEvent[] }> {
  const events: EgressGateEvent[] = [];
  const options: ExclusiveEgressGateOptions = {
    policy: { agent_uid: AGENT_UID, gate_port: 19998 },
    rules: [],
    livenessProbe: liveProbe,
    clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
    peerRunner: peerRunnerReporting(AGENT_UID),
    onEvent: (e) => events.push(e),
    isRoutable: () => true,
    ...overrides,
  };
  const server = createExclusiveEgressGate(options);
  await new Promise<void>((resolve) => server.listen(0, GATE_BIND_HOST, resolve));
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return { port: (server.address() as AddressInfo).port, events };
}

const validHeader = formatGateCredentialHeader({ generation_id: GEN, secret: SECRET });

describe("egress-gate/gate-server TCB fail-closed client auth", () => {
  it("DENIES an anonymous CONNECT (no credential) with 403 + client_denied(no_credential)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startTcbGate({ rules: [allowRule("127.0.0.1", upstream.port)] });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`); // no Proxy-Authorization
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("no_credential");
    // never reached the destination decision
    expect(events.some((e) => e.kind === "decision")).toBe(false);
  });

  it("DENIES a valid credential from the WRONG peer uid (bearer never overrides peer)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startTcbGate({
      rules: [allowRule("127.0.0.1", upstream.port)],
      peerRunner: peerRunnerReporting(501), // operator, not the agent
    });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("peer_uid_mismatch");
    expect(denied && denied.kind === "client_denied" && denied.peerUid).toBe(501);
  });

  it("DENIES a valid credential when the peer cannot be resolved (unresolved => deny)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startTcbGate({
      rules: [allowRule("127.0.0.1", upstream.port)],
      peerRunner: peerRunnerUnresolving,
    });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("peer_unresolved");
  });

  it("DENIES a stale-generation credential (no old-token replay)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startTcbGate({ rules: [allowRule("127.0.0.1", upstream.port)] });
    const stale = formatGateCredentialHeader({ generation_id: GEN - 1, secret: SECRET });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, stale);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("stale_generation");
  });

  it("DENIES every CONNECT when no peerRunner is configured (fail-closed, peer always unresolved)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startTcbGate({
      rules: [allowRule("127.0.0.1", upstream.port)],
      peerRunner: undefined,
    });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("peer_unresolved");
  });

  it("ALLOWS a valid credential from the matching peer (tunnels to the upstream)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startTcbGate({ rules: [allowRule("127.0.0.1", upstream.port)] });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 200 Connection Established");
    expect(result.body).toContain("upstream-hello");
    expect(events.some((e) => e.kind === "client_denied")).toBe(false);
    const decision = events.find((e) => e.kind === "decision");
    expect(decision && decision.kind === "decision" && decision.decision.disposition).toBe("allow");
  });

  it("REFUSES to construct when clientAuth is bound to a different uid than the policy (Codex F1)", () => {
    expect(() =>
      createExclusiveEgressGate({
        policy: { agent_uid: AGENT_UID, gate_port: 19998 },
        rules: [],
        livenessProbe: liveProbe,
        clientAuth: createGateClientAuthenticator({ agentUid: 501, acceptSource }),
      }),
    ).toThrow(/must equal policy\.agent_uid/);
  });

  it("REFUSES to construct when the liveness probe advertises a mismatched binding (Codex F3)", () => {
    const misboundProbe: GateLivenessProbe = {
      binding: { agentUid: 999, gatePort: 19998 },
      check: () => Promise.resolve({ live: true, reasons: [] }),
    };
    expect(() =>
      createExclusiveEgressGate({
        policy: { agent_uid: AGENT_UID, gate_port: 19998 },
        rules: [],
        livenessProbe: misboundProbe,
      }),
    ).toThrow(/cross-principal liveness verdict/);
  });

  it("accepts a probe whose advertised binding matches the policy", () => {
    const boundProbe: GateLivenessProbe = {
      binding: { agentUid: AGENT_UID, gatePort: 19998 },
      check: () => Promise.resolve({ live: true, reasons: [] }),
    };
    expect(() =>
      createExclusiveEgressGate({
        policy: { agent_uid: AGENT_UID, gate_port: 19998 },
        rules: [],
        livenessProbe: boundProbe,
      }),
    ).not.toThrow();
  });

  it("singleFlightLiveness:false runs a fresh probe per CONNECT (closes the post-flush shared-green window, Codex F4)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    let probes = 0;
    let live = true;
    const { port } = await startTcbGate({
      rules: [allowRule("127.0.0.1", upstream.port)],
      singleFlightLiveness: false,
      livenessProbe: {
        check: () => {
          probes += 1;
          return Promise.resolve({ live, reasons: live ? [] : ["flushed"] });
        },
      },
    });
    const first = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(first.statusLine).toBe("HTTP/1.1 200 Connection Established");
    // A flush between CONNECTs: the next CONNECT runs its OWN probe and denies.
    live = false;
    const second = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(second.statusLine).toBe("HTTP/1.1 503 Service Unavailable");
    expect(probes).toBe(2); // no shared in-flight verdict
  });

  it("captures dependencies at construction: mutating options.clientAuth/livenessProbe afterwards does NOT change enforcement (Codex round-5 chokepoint)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const events: EgressGateEvent[] = [];
    // Build a real options object we retain a reference to, then mutate it after
    // construction. A gate that re-dereferenced options.* per CONNECT would pick
    // up the swaps; the chokepoint captures at construction so it must not.
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      onEvent: (e) => events.push(e),
      isRoutable: () => true,
    };
    const server = createExclusiveEgressGate(options);
    await new Promise<void>((resolve) => server.listen(0, GATE_BIND_HOST, resolve));
    cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
    const port = (server.address() as AddressInfo).port;

    // Swap in hostile/dead dependencies AFTER construction.
    options.clientAuth = createGateClientAuthenticator({ agentUid: 999, acceptSource });
    options.livenessProbe = { check: () => Promise.resolve({ live: false, reasons: ["swapped-dead"] }) };
    options.peerRunner = peerRunnerReporting(999);
    options.rules = []; // would default-deny if re-read

    // The gate still enforces the ORIGINAL captured config: a valid AGENT_UID
    // credential from the matched AGENT_UID peer tunnels (proves it did NOT pick
    // up the dead probe, the uid-999 authenticator, or the emptied rules).
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 200 Connection Established");
    expect(events.some((e) => e.kind === "client_denied")).toBe(false);
  });

  it("deep-freezes a CLONE of the rules: in-place mutation of the caller's array after construction does NOT widen policy (round-6)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // Construct default-deny (empty rules) in TCB mode.
    const callerRules: AllowlistRule[] = [];
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: callerRules,
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      isRoutable: () => true,
    };
    const server = createExclusiveEgressGate(options);
    await new Promise<void>((resolve) => server.listen(0, GATE_BIND_HOST, resolve));
    cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
    const port = (server.address() as AddressInfo).port;

    // Default-deny holds even with a valid credential + matched peer.
    const denied = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(denied.statusLine).toBe("HTTP/1.1 403 Forbidden");

    // Mutate the caller's SAME array in place to try to widen policy.
    callerRules.push(allowRule("127.0.0.1", upstream.port));
    const stillDenied = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(stillDenied.statusLine).toBe("HTTP/1.1 403 Forbidden"); // the frozen clone is unchanged
  });

  it("binds injected-op METHODS at construction: swapping livenessProbe.check / peerRunner.run afterwards is inert (round-7)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const liveProbeObj: GateLivenessProbe = { check: () => Promise.resolve({ live: true, reasons: [] }) };
    const peerRunnerObj = peerRunnerReporting(AGENT_UID);
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: liveProbeObj,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerObj,
      isRoutable: () => true,
    };
    const server = createExclusiveEgressGate(options);
    await new Promise<void>((resolve) => server.listen(0, GATE_BIND_HOST, resolve));
    cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
    const port = (server.address() as AddressInfo).port;

    // Swap the METHODS on the same objects after construction: dead liveness +
    // a peer runner that reports a hostile uid. Bound-at-construction methods
    // ignore the swap.
    liveProbeObj.check = () => Promise.resolve({ live: false, reasons: ["swapped-dead"] });
    peerRunnerObj.run = (_c, args) => {
      const portArg = /:(\d+)$/.exec(args[2] ?? "");
      const clientPort = portArg ? Number(portArg[1]) : 0;
      return Promise.resolve({ code: 0, stdout: [`p1`, `u999`, `n127.0.0.1:${clientPort}->127.0.0.1:x`, ""].join("\n") });
    };
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 200 Connection Established"); // original check + runner still used
  });

  it("composes with the oracle liveness probe: a flushed (invalidated) token denies the next CONNECT with 503", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const store = new Map<number, string>();
    let clock = 1_000;
    const ops: LivenessOracleOps = {
      writeToken: (uid, payload) => {
        store.set(uid, payload);
        return Promise.resolve();
      },
      removeToken: (uid) => {
        store.delete(uid);
        return Promise.resolve();
      },
      probe: (): Promise<PfLivenessResult> => Promise.resolve({ live: true, reasons: [] }),
      now: () => clock,
    };
    const source: LivenessTokenSource = { read: (uid) => Promise.resolve(store.get(uid) ?? null) };
    // The oracle binding MUST match the gate policy {agent_uid, gate_port} or
    // the F3 construction guard refuses (proven in its own test above).
    const oracleBinding = { agentUid: AGENT_UID, gatePort: 19998, generationId: GEN };
    const oracle = new GateLivenessOracle(privateKey, ops, { ttlMs: 60_000 });
    await oracle.refresh(oracleBinding);
    const livenessProbe = createOracleLivenessProbe({
      source,
      publicKey,
      binding: oracleBinding,
      now: () => clock,
    });

    const { port } = await startTcbGate({
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe,
      singleFlightLiveness: false, // per-CONNECT freshness (the F4 recommendation for the oracle probe)
    });
    // First CONNECT: live token + valid credential + matched peer -> tunnels.
    const first = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(first.statusLine).toBe("HTTP/1.1 200 Connection Established");
    // Flush: the supervisor invalidates the liveness token.
    await oracle.invalidate(AGENT_UID);
    const second = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(second.statusLine).toBe("HTTP/1.1 503 Service Unavailable");
  });
});

// ---------------------------------------------------------------------------
// singleFlightLiveness CONSTRUCTION GUARD (pre-S5-6 wiring-footgun closure).
// A binding-declaring (oracle) probe must never run under single-flight
// coalescing: the guard auto-disables it when the option is omitted and
// REFUSES construction when the caller explicitly asked for `true`. A
// binding-less legacy probe keeps the unchanged single-flight default.
// ---------------------------------------------------------------------------
describe("egress-gate/gate-server singleFlightLiveness construction guard", () => {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  /** A probe whose check() stays pending until resolved, counting calls. */
  function pendingCountingProbe(binding?: { agentUid: number; gatePort: number }) {
    let calls = 0;
    const resolvers: Array<(r: PfLivenessResult) => void> = [];
    const probe: GateLivenessProbe = {
      ...(binding !== undefined ? { binding } : {}),
      check: () =>
        new Promise<PfLivenessResult>((res) => {
          calls += 1;
          resolvers.push(res);
        }),
    };
    return {
      probe,
      get calls() {
        return calls;
      },
      resolveAll(r: PfLivenessResult) {
        for (const f of resolvers.splice(0)) f(r);
      },
    };
  }

  /** Start a legacy (no clientAuth) gate on an ephemeral port. */
  async function startLegacyGate(
    livenessProbe: GateLivenessProbe,
    singleFlightLiveness?: boolean,
  ): Promise<number> {
    const server = createExclusiveEgressGate({
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [],
      livenessProbe,
      ...(singleFlightLiveness !== undefined ? { singleFlightLiveness } : {}),
    });
    await new Promise<void>((resolve) => server.listen(0, GATE_BIND_HOST, resolve));
    cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
    return (server.address() as AddressInfo).port;
  }

  it("AUTO-DISABLES single-flight for a binding-declaring probe with default options (per-CONNECT probes)", async () => {
    const pc = pendingCountingProbe({ agentUid: AGENT_UID, gatePort: 19998 });
    const port = await startLegacyGate(pc.probe); // no singleFlightLiveness option at all
    const connects = [
      rawConnect(port, "example.com:443"),
      rawConnect(port, "example.com:443"),
      rawConnect(port, "example.com:443"),
    ];
    await sleep(80);
    // Auto-disabled: every concurrent CONNECT ran its OWN probe. Under the old
    // default-true behavior this would be 1 (the post-flush shared-green window).
    expect(pc.calls).toBe(3);
    pc.resolveAll({ live: false, reasons: ["flushed"] });
    for (const p of connects) expect((await p).statusLine).toContain("503");
  });

  it("REFUSES to construct a binding-declaring probe with explicit singleFlightLiveness:true (never silently honored)", () => {
    const boundProbe: GateLivenessProbe = {
      binding: { agentUid: AGENT_UID, gatePort: 19998 },
      check: () => Promise.resolve({ live: true, reasons: [] }),
    };
    expect(() =>
      createExclusiveEgressGate({
        policy: { agent_uid: AGENT_UID, gate_port: 19998 },
        rules: [],
        livenessProbe: boundProbe,
        singleFlightLiveness: true,
      }),
    ).toThrow(/singleFlightLiveness:true is incompatible with a binding-declaring/);
  });

  it("still accepts a binding-declaring probe with explicit singleFlightLiveness:false (the S5-6 wiring)", () => {
    const boundProbe: GateLivenessProbe = {
      binding: { agentUid: AGENT_UID, gatePort: 19998 },
      check: () => Promise.resolve({ live: true, reasons: [] }),
    };
    expect(() =>
      createExclusiveEgressGate({
        policy: { agent_uid: AGENT_UID, gate_port: 19998 },
        rules: [],
        livenessProbe: boundProbe,
        singleFlightLiveness: false,
      }),
    ).not.toThrow();
  });

  it("keeps the single-flight DEFAULT for a binding-less legacy probe (one shared probe for concurrent CONNECTs)", async () => {
    const pc = pendingCountingProbe(); // no binding => legacy pf-probe shape
    const port = await startLegacyGate(pc.probe); // default options
    const connects = [
      rawConnect(port, "example.com:443"),
      rawConnect(port, "example.com:443"),
      rawConnect(port, "example.com:443"),
    ];
    await sleep(80);
    expect(pc.calls).toBe(1); // unchanged: shared in-flight probe bounds pfctl amplification
    pc.resolveAll({ live: false, reasons: ["denied"] });
    for (const p of connects) expect((await p).statusLine).toContain("503");
  });

  it("keeps explicit singleFlightLiveness:true working for a binding-less probe (no behavior change off the oracle path)", async () => {
    const pc = pendingCountingProbe();
    const port = await startLegacyGate(pc.probe, true);
    const connects = [rawConnect(port, "example.com:443"), rawConnect(port, "example.com:443")];
    await sleep(80);
    expect(pc.calls).toBe(1);
    pc.resolveAll({ live: false, reasons: ["denied"] });
    for (const p of connects) expect((await p).statusLine).toContain("503");
  });
});
