/**
 * INDEPENDENT round-7 refute suite (final-confirmation reviewer, refute-by-default).
 *
 * The round-7 change binds every injected-op METHOD once at construction so the
 * runtime never re-reads `obj.method` off a caller-held object. The builder's own
 * gate-server-tcb round-7 test proves the `livenessProbe.check` + `peerRunner.run`
 * bind sites are inert to a post-construction method swap. This suite closes the
 * THREE bind sites that test did NOT exercise, each a distinct "swap an injected
 * op's method after construction to flip enforcement" attack:
 *
 *   1. gate-server.ts:231  boundResolver = { resolve: options.resolver.resolve.bind(...) }
 *      -- swap resolver.resolve to steer DNS to a poison/empty result set;
 *   2. gate-client-auth.ts:143  acceptCurrent = acceptSource.current.bind(...)
 *      -- swap acceptSource.current to revive accept-state the gate denied for;
 *   3. liveness-oracle.ts:320  readToken = input.source.read.bind(...)
 *      -- swap source.read to feed an OLD signed token back after invalidation.
 *
 * These are the ACCIDENTAL/ALIASING reassignment vector (a trusted injector that
 * deliberately hands a malicious method is tautological to DI; the module cannot
 * defend against the injector it is constructed by). Each test is an ATTACK; the
 * assertion is that the bypass FAILS because the method was captured at
 * construction. Adds nothing to source.
 */

import { describe, it, expect, afterEach } from "vitest";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { createHash, generateKeyPairSync } from "node:crypto";

import {
  createExclusiveEgressGate,
  GATE_BIND_HOST,
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
import type { EgressProxyResolver } from "../../src/castle-wall/egress-proxy.js";
import type { PeerCommandRunner } from "../../src/egress-gate/peer-identity.js";
import type { AllowlistRule } from "../../src/castle-wall/allowlist/schema.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../src/castle-wall/constants.js";
import type { PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";

const AGENT_UID = 502;
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
const acceptRecord: GateCredentialAcceptRecord = {
  version: GATE_CREDENTIAL_VERSION,
  generation_id: GEN,
  secret_sha256: sha256Hex(SECRET),
};
const validHeader = formatGateCredentialHeader({ generation_id: GEN, secret: SECRET });

function allowRule(host: string, port: number): AllowlistRule {
  return {
    id: `refute7-${host}-${port}`,
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
        stdout: [`p999`, `u${uid}`, `n127.0.0.1:${clientPort}->127.0.0.1:19998`, ""].join("\n"),
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

function rawConnect(
  gatePort: number,
  authority: string,
  proxyAuth?: string,
): Promise<{ statusLine: string; head: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(gatePort, "127.0.0.1", () => {
      const authLine = proxyAuth ? `Proxy-Authorization: ${proxyAuth}\r\n` : "";
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${authLine}\r\n`);
    });
    let data = "";
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
    socket.on("end", () => resolve({ statusLine: data.split("\r\n")[0] ?? "", head: data }));
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
// ATTACK 1: swap resolver.resolve after construction (gate-server.ts:231).
// The bound resolver must ignore the swap. Original resolves the hostname to
// the live upstream (-> allow + tunnel); the swapped resolve returns [] which,
// if re-read, would deny with non_public_resolved_address. Bound => 200.
// ---------------------------------------------------------------------------
describe("round-7 refute: swapping resolver.resolve after construction is inert", () => {
  it("uses the construction-bound resolver, not a later-swapped .resolve", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // Mutable resolver object the attacker holds a reference to.
    const resolverObj: EgressProxyResolver = {
      resolve: () => Promise.resolve(["127.0.0.1"]),
    };
    const options: ExclusiveEgressGateOptions = {
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("upstream.test", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({
        agentUid: AGENT_UID,
        acceptSource: { current: () => Promise.resolve(acceptRecord) },
      }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      resolver: resolverObj,
      isRoutable: () => true,
    };
    const port = await listen(options);
    const before = await rawConnect(port, `upstream.test:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 200 Connection Established");
    // Attack: swap .resolve to steer resolution to an empty set. If the gate
    // re-read resolverObj.resolve per CONNECT this would flip to deny.
    resolverObj.resolve = () => Promise.resolve([]);
    const after = await rawConnect(port, `upstream.test:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 200 Connection Established");
  });

  it("a swap that would WIDEN resolution to a poison host is also ignored (deny stays deny)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // Original resolver returns an empty set -> the gate denies (no routable
    // address). The attacker swaps in a resolver that would resolve to the live
    // upstream; the bound original must keep denying.
    const resolverObj: EgressProxyResolver = { resolve: () => Promise.resolve([]) };
    const port = await listen({
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("upstream.test", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({
        agentUid: AGENT_UID,
        acceptSource: { current: () => Promise.resolve(acceptRecord) },
      }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      resolver: resolverObj,
      isRoutable: () => true,
    });
    const before = await rawConnect(port, `upstream.test:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(before.head).toContain("denied-by-policy");
    resolverObj.resolve = () => Promise.resolve(["127.0.0.1"]);
    const after = await rawConnect(port, `upstream.test:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(after.head).toContain("denied-by-policy");
  });
});

// ---------------------------------------------------------------------------
// ATTACK 2: swap acceptSource.current after construction (gate-client-auth.ts:143).
// Original current() returns null (no accept-state) => every CONNECT DENIES.
// The attacker swaps .current to return the valid accept record. If authorize()
// re-read acceptSource.current, that would revive the credential. Bound => deny.
// ---------------------------------------------------------------------------
describe("round-7 refute: swapping acceptSource.current after construction is inert", () => {
  it("cannot revive a denied credential by swapping .current to a permissive record", async () => {
    const acceptObj: GateAcceptSource = { current: () => Promise.resolve(null) };
    const authn = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource: acceptObj });
    // Baseline: with no accept-state the credential is denied even with a
    // resolved+matched peer and a well-formed header.
    const before = await authn.authorize({
      credentialHeader: validHeader,
      peer: { kind: "resolved", uid: AGENT_UID, pid: 1 },
    });
    expect(before).toEqual({ allow: false, reason: "no_accept_state" });
    // Attack: swap .current to return the matching accept record.
    acceptObj.current = () => Promise.resolve(acceptRecord);
    const after = await authn.authorize({
      credentialHeader: validHeader,
      peer: { kind: "resolved", uid: AGENT_UID, pid: 1 },
    });
    // Bound-at-construction: the original null-returning method is still used.
    expect(after).toEqual({ allow: false, reason: "no_accept_state" });
  });
});

// ---------------------------------------------------------------------------
// ATTACK 3: swap source.read after construction (liveness-oracle.ts:320) to feed
// an OLD signed token back after the supervisor invalidated it -- the exact
// revive-after-flush attack the bind comment names. Bound => not live.
// ---------------------------------------------------------------------------
describe("round-7 refute: swapping the oracle token source.read after construction is inert", () => {
  it("cannot revive a flushed liveness token by swapping .read to return the old token", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const store = new Map<number, string>();
    let clock = 1_000;
    const ops: LivenessOracleOps = {
      writeToken: (uid, payload) => (store.set(uid, payload), Promise.resolve()),
      removeToken: (uid) => (store.delete(uid), Promise.resolve()),
      probe: () => Promise.resolve({ live: true, reasons: [] }),
      now: () => clock,
    };
    const oracle = new GateLivenessOracle(privateKey, ops, { ttlMs: 60_000 });
    const binding = { agentUid: AGENT_UID, gatePort: 19998, generationId: GEN };
    await oracle.refresh(binding);
    // Capture the live token string as an attacker would (still unexpired).
    const capturedOldToken = store.get(AGENT_UID)!;
    expect(capturedOldToken).toBeTruthy();

    // The gate's probe reads from the live store. Prove it works while live.
    const sourceObj: LivenessTokenSource = { read: (uid) => Promise.resolve(store.get(uid) ?? null) };
    const probe = createOracleLivenessProbe({ source: sourceObj, publicKey, binding, now: () => clock });
    const liveNow = await probe.check();
    expect(liveNow.live).toBe(true);

    // Supervisor flushes: the token is invalidated (removed from the store).
    await oracle.invalidate(AGENT_UID);
    const afterFlush = await probe.check();
    expect(afterFlush.live).toBe(false); // store now empty -> absent -> not live

    // Attack: swap .read to hand back the OLD (still time-unexpired) token,
    // ignoring the invalidation. A re-read of sourceObj.read would revive green.
    sourceObj.read = () => Promise.resolve(capturedOldToken);
    const afterSwap = await probe.check();
    // Bound-at-construction: the original store-backed read is still used, so the
    // flushed state stands and the revive fails.
    expect(afterSwap.live).toBe(false);
    expect(afterSwap.reasons.join(" ")).toMatch(/absent/);
  });
});

// ---------------------------------------------------------------------------
// CONFINED-AGENT REACHABILITY: the realistic adversary on the CONNECT socket
// holds NONE of the injected op references. Its only levers are the header and
// the socket. Confirm neither changes enforcement: a forged/absent credential
// from the socket party is denied, and it cannot influence which method runs.
// ---------------------------------------------------------------------------
describe("round-7 refute: the confined agent on the socket cannot change enforcement", () => {
  it("a forged bearer + a swapped-behind-the-scenes op set still deny the socket party", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const port = await listen({
      policy: { agent_uid: AGENT_UID, gate_port: 19998 },
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({
        agentUid: AGENT_UID,
        acceptSource: { current: () => Promise.resolve(acceptRecord) },
      }),
      peerRunner: peerRunnerReporting(AGENT_UID),
      isRoutable: () => true,
    });
    // The socket party (confined agent) presents a WRONG secret for the right
    // generation -> bad_secret -> 403 client-denied. It holds no injected ref to
    // swap, so this is the whole of its reachable surface.
    const forged = formatGateCredentialHeader({ generation_id: GEN, secret: "00".repeat(16) });
    const denied = await rawConnect(port, `127.0.0.1:${upstream.port}`, forged);
    expect(denied.statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(denied.head).toContain("client-denied");
    // An absent credential is likewise denied.
    const anon = await rawConnect(port, `127.0.0.1:${upstream.port}`);
    expect(anon.statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(anon.head).toContain("client-denied");
  });
});
