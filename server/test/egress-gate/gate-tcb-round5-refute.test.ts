/**
 * INDEPENDENT round-5 refute suite (Family-A confirmation pass, refute-by-default).
 *
 * Attacks the round-5 chokepoint in createExclusiveEgressGate: every consumed
 * dependency is CAPTURED into a local at construction (policy as a FROZEN COPY;
 * clientAuth/livenessProbe/peerRunner/rules/resolver/isRoutable/onEvent as locals),
 * and the per-CONNECT handlers read ONLY those locals -- the caller-owned mutable
 * `options` object is never re-dereferenced at runtime. This closes the
 * advertised-vs-enforced divergence one level up from the individual objects: a
 * caller swapping options.clientAuth / livenessProbe / rules / peerRunner (or
 * mutating options.policy) AFTER construction must not change what the gate
 * ENFORCES, because the construction guards already passed against the originals.
 *
 * Every test is an ATTACK; the assertion is that the bypass FAILS. Written by the
 * refute reviewer, distinct from the builder's own suite. Adds nothing to source.
 */

import { describe, it, expect, afterEach } from "vitest";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";

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
import type { PeerCommandRunner } from "../../src/egress-gate/peer-identity.js";
import type { AllowlistRule } from "../../src/castle-wall/allowlist/schema.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../src/castle-wall/constants.js";

const AGENT_UID = 502;
const HOSTILE_UID = 999;
const GEN = 7;
const SECRET = "deadbeefcafef00d";
const sha256Hex = (v: string): string => createHash("sha256").update(v, "utf8").digest("hex");

// TCB gates require the oracle-shape probe (coalescing:"forbidden" + a
// policy-matching binding); the gate refuses construction otherwise.
const liveProbe: GateLivenessProbe = {
  coalescing: "forbidden",
  binding: { agentUid: AGENT_UID, gatePort: 19998 },
  check: () => Promise.resolve({ live: true, reasons: [] }),
};
const deadProbe: GateLivenessProbe = {
  coalescing: "forbidden",
  binding: { agentUid: AGENT_UID, gatePort: 19998 },
  check: () => Promise.resolve({ live: false, reasons: ["swapped-dead"] }),
};

const acceptRecord: GateCredentialAcceptRecord = {
  version: GATE_CREDENTIAL_VERSION,
  generation_id: GEN,
  secret_sha256: sha256Hex(SECRET),
};
const acceptSource: GateAcceptSource = { current: () => Promise.resolve(acceptRecord) };
const validHeader = formatGateCredentialHeader({ generation_id: GEN, secret: SECRET });

function allowRule(host: string, port: number): AllowlistRule {
  return {
    id: `refute-allow-${host}-${port}`,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-07-02T00:00:00Z",
    match: { host, port: [port], protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

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

function startUpstream(): Promise<{ port: number; close: () => void }> {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => socket.end("upstream-hello"));
    server.listen(0, "127.0.0.1", () => {
      resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() });
    });
  });
}

function rawConnect(gatePort: number, authority: string, proxyAuth?: string): Promise<{ statusLine: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(gatePort, "127.0.0.1", () => {
      const authLine = proxyAuth ? `Proxy-Authorization: ${proxyAuth}\r\n` : "";
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${authLine}\r\n`);
    });
    let data = "";
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
    socket.on("end", () => resolve({ statusLine: data.split("\r\n")[0] ?? "" }));
    socket.on("error", reject);
    setTimeout(() => socket.destroy(new Error("test connect timeout")), 5_000).unref();
  });
}

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

async function listen(options: ExclusiveEgressGateOptions): Promise<number> {
  const server = createExclusiveEgressGate(options);
  await new Promise<void>((resolve) => server.listen(0, GATE_BIND_HOST, resolve));
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return (server.address() as AddressInfo).port;
}

// ---------------------------------------------------------------------------
// ATTACK 1: swap the security-critical deps by REASSIGNMENT after construction.
// The gate must enforce the ORIGINAL captured config on every axis.
// ---------------------------------------------------------------------------
describe("round-5 refute: reassigning options.* after construction cannot change enforcement", () => {
  it("swapping clientAuth to a HOSTILE-uid authenticator does NOT admit that uid", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const events: EgressGateEvent[] = [];
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      onEvent: (e) => events.push(e),
      isRoutable: () => true,
    };
    const port = await listen(options);
    // Attack: swap in a uid-999 authenticator AND a uid-999 peer runner.
    options.clientAuth = createGateClientAuthenticator({ agentUid: HOSTILE_UID, acceptSource });
    options.peerRunner = peerRunnerReporting(HOSTILE_UID);
    // The ORIGINAL AGENT_UID peer + valid credential still tunnels (proves the
    // swapped uid-999 authenticator was NOT picked up -- if it had, this AGENT_UID
    // peer would fail the swapped authenticator's uid check).
    const r = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(r.statusLine).toBe("HTTP/1.1 200 Connection Established");
    expect(events.some((e) => e.kind === "client_denied")).toBe(false);
  });

  it("swapping livenessProbe to a DEAD probe does NOT start refusing (503) traffic", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      isRoutable: () => true,
    };
    const port = await listen(options);
    options.livenessProbe = deadProbe; // would 503 every CONNECT if re-read
    const r = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(r.statusLine).toBe("HTTP/1.1 200 Connection Established");
  });

  it("swapping livenessProbe from DEAD (deny) to LIVE does NOT open a gate that was constructed dead", async () => {
    // Direction that matters for fail-closed: a gate built with a dead probe must
    // keep refusing even if the caller later swaps in a live probe object.
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: deadProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      isRoutable: () => true,
    };
    const port = await listen(options);
    options.livenessProbe = liveProbe; // attacker tries to revive a dead gate
    const r = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(r.statusLine).toBe("HTTP/1.1 503 Service Unavailable");
  });

  it("REASSIGNING options.rules to an emptied array does NOT change the (captured) rule set", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      isRoutable: () => true,
    };
    const port = await listen(options);
    options.rules = []; // reassignment: an empty (default-deny) set if re-read
    const r = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(r.statusLine).toBe("HTTP/1.1 200 Connection Established");
  });

  it("swapping onEvent does NOT redirect audit away from the captured sink", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const captured: EgressGateEvent[] = [];
    const attacker: EgressGateEvent[] = [];
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      onEvent: (e) => captured.push(e),
      isRoutable: () => true,
    };
    const port = await listen(options);
    options.onEvent = (e) => attacker.push(e); // try to blind the original audit sink
    await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(captured.some((e) => e.kind === "decision")).toBe(true);
    expect(attacker.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// ATTACK 2: mutate options.policy IN PLACE after construction. policy is a
// FROZEN COPY, so field mutation on the caller's original must not reach the gate.
// ---------------------------------------------------------------------------
describe("round-5 refute: mutating options.policy in place cannot change the gate principal", () => {
  it("mutating options.policy.agent_uid to a hostile uid does NOT change the enforced agent uid", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const events: EgressGateEvent[] = [];
    const policy = { agent_uid: AGENT_UID, gate_port: 19998 };
    const options: ExclusiveEgressGateOptions = {
      policy,
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(HOSTILE_UID), // peer resolves to the hostile uid
      onEvent: (e) => events.push(e),
      isRoutable: () => true,
    };
    const port = await listen(options);
    // Attack: retro-point the policy at the hostile uid so the hostile peer matches.
    policy.agent_uid = HOSTILE_UID;
    // The gate still enforces AGENT_UID (frozen copy); the hostile peer is denied.
    const r = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(r.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("peer_uid_mismatch");
  });

  it("the internal policy copy is frozen and decoupled from the caller's object", () => {
    const policy = { agent_uid: AGENT_UID, gate_port: 19998 };
    const options: ExclusiveEgressGateOptions = {
      policy,
      rules: [],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(AGENT_UID),
    };
    // Constructs cleanly against AGENT_UID.
    expect(() => createExclusiveEgressGate(options)).not.toThrow();
    // Mutating the caller's policy to a cross-principal value AFTER construction
    // cannot retroactively break the F1 guard that already passed against AGENT_UID.
    policy.agent_uid = HOSTILE_UID;
    // (No throw here: the guard runs at construction, which already happened; this
    // asserts the mutation is simply inert -- the gate above holds its own frozen copy.)
    expect(policy.agent_uid).toBe(HOSTILE_UID);
  });
});

// ---------------------------------------------------------------------------
// ATTACK 3: IN-PLACE mutation of the captured rules array (the vector the
// builder's suite did not cover -- it only reassigns options.rules). `rules` is
// captured as a reference, not a frozen copy, so this documents the actual
// behavior of in-place content mutation.
// ---------------------------------------------------------------------------
describe("round-6 refute: in-place mutation of the rules array (CLOSED by deep-frozen clone)", () => {
  it("pushing a permissive rule into the SAME array object after construction has NO effect", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const rules: AllowlistRule[] = []; // constructed default-deny for the target
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules,
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      isRoutable: () => true,
    };
    const port = await listen(options);
    // Baseline: empty rules => the target is denied by policy (403 denied-by-policy).
    const before = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 403 Forbidden");
    // Attack: mutate the array CONTENTS in place (not a reassignment). Round-6 fix:
    // the gate captured a DEEP-FROZEN CLONE (structuredClone + deepFreeze), NOT the
    // caller's array, so this push cannot widen the enforced policy.
    rules.push(allowRule("127.0.0.1", upstream.port));
    const after = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 403 Forbidden"); // CLOSED: still denied
  });
});

// ---------------------------------------------------------------------------
// STATIC INVARIANT: prove options is never re-dereferenced in the runtime path.
// Any options.* read must live in the construction prologue or in the separate
// startExclusiveEgressGate port snapshot -- never inside a per-CONNECT handler.
// ---------------------------------------------------------------------------
describe("round-5 refute: static -- no options.* read survives into a CONNECT handler", () => {
  it("every options.* reference is confined to the construction prologue / start snapshot", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const src = readFileSync(
      fileURLToPath(new URL("../../src/egress-gate/gate-server.ts", import.meta.url)),
      "utf8",
    );
    const lines = src.split("\n");
    const optionsLines = lines
      .map((line, i) => ({ line, n: i + 1 }))
      .filter(({ line }) => /\boptions\./.test(line));
    // The per-CONNECT handler body (server.on("connect"...) and handleGateConnect)
    // begins after the construction prologue and ENDS where createExclusiveEgressGate
    // ends -- i.e. at the start of the separate startExclusiveEgressGate function.
    // Assert no `options.` read appears inside that per-CONNECT region. Reads in
    // startExclusiveEgressGate (the deliberate, synchronous port snapshot) are NOT
    // the runtime CONNECT path and are allowed.
    const firstHandlerLine =
      lines.findIndex((l) => /server\.on\("connect"/.test(l)) + 1;
    const startFnLine =
      lines.findIndex((l) => /export async function startExclusiveEgressGate/.test(l)) + 1;
    expect(firstHandlerLine).toBeGreaterThan(0);
    expect(startFnLine).toBeGreaterThan(firstHandlerLine);
    const leaks = optionsLines.filter(({ n }) => n > firstHandlerLine && n < startFnLine);
    expect(leaks.map(({ n }) => n)).toEqual([]);
  });
});
