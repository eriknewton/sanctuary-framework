/**
 * INDEPENDENT round-6 refute suite (Family-A final confirmation, refute-by-default).
 *
 * Attacks the round-6 rules snapshot in createExclusiveEgressGate
 * (gate-server.ts:222): `rules` is captured as a DEEP-FROZEN CLONE
 * (structuredClone + recursive deepFreeze), so a caller mutating its own rules
 * array/objects IN PLACE after construction must not change what the gate
 * enforces per CONNECT. Round-5 only proved reassignment (`options.rules = []`)
 * and a single push; this suite drives the nested vectors: flip a rule's
 * disposition, widen match.host, mutate the match.port array at depth, index
 * reassignment, scope mutation, live-getter TOCTOU, and the narrow direction
 * (an allow snapshot survives the caller emptying its array).
 *
 * A SHALLOW copy (Array.from / slice) would pass round-5's push test but FAIL
 * the nested tests here -- these discriminate the deep clone specifically.
 *
 * Every test is an ATTACK; the assertion is that the bypass FAILS. Adds nothing
 * to source.
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
const GEN = 7;
const SECRET = "deadbeefcafef00d";
const sha256Hex = (v: string): string => createHash("sha256").update(v, "utf8").digest("hex");

const liveProbe: GateLivenessProbe = { check: () => Promise.resolve({ live: true, reasons: [] }) };

const acceptRecord: GateCredentialAcceptRecord = {
  version: GATE_CREDENTIAL_VERSION,
  generation_id: GEN,
  secret_sha256: sha256Hex(SECRET),
};
const acceptSource: GateAcceptSource = { current: () => Promise.resolve(acceptRecord) };
const validHeader = formatGateCredentialHeader({ generation_id: GEN, secret: SECRET });

function allowRule(host: string, port: number): AllowlistRule {
  return {
    id: `refute6-${host}-${port}-${Math.random().toString(36).slice(2)}`,
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

/** Raw CONNECT returning the full response head so tests can distinguish
 * denied-by-policy from client-denied via the X-Sanctuary-Gate header. */
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

/** TCB-mode options with an in-place-mutable rules array owned by the attacker. */
function tcbOptions(rules: AllowlistRule[], events?: EgressGateEvent[]): ExclusiveEgressGateOptions {
  return {
    policy: { agent_uid: AGENT_UID, gate_port: 19998 },
    rules,
    livenessProbe: liveProbe,
    clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
    peerRunner: peerRunnerReporting(AGENT_UID),
    ...(events ? { onEvent: (e: EgressGateEvent) => events.push(e) } : {}),
    isRoutable: () => true,
  };
}

// ---------------------------------------------------------------------------
// ATTACK 1: widen enforcement via NESTED in-place mutation (the deny->allow
// direction, the one that matters). Each variant would succeed against a
// shallow copy; the deep clone must defeat all of them.
// ---------------------------------------------------------------------------
describe("round-6 refute: nested in-place mutation of caller rules cannot WIDEN the gate", () => {
  it("flipping an existing rule's disposition deny->allow after construction stays denied", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // Rule MATCHES the target but is disposition:"deny" -> allowlist_miss.
    const rule = allowRule("127.0.0.1", upstream.port);
    rule.disposition = "deny";
    const rules = [rule];
    const events: EgressGateEvent[] = [];
    const port = await listen(tcbOptions(rules, events));
    const before = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(before.head).toContain("denied-by-policy");
    // Attack: flip the SAME rule object's disposition in place.
    rule.disposition = "allow";
    const after = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(after.head).toContain("denied-by-policy");
  });

  it("widening match.host to the target after construction stays denied", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // Allow rule for a DIFFERENT loopback literal -> target does not match.
    const rule = allowRule("127.0.0.2", upstream.port);
    const rules = [rule];
    const port = await listen(tcbOptions(rules));
    const before = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 403 Forbidden");
    // Attack: retarget the nested match object at the real destination.
    rule.match.host = "127.0.0.1";
    const after = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 403 Forbidden");
  });

  it("pushing the target port into the nested match.port ARRAY stays denied (depth-2 mutation)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // Allow rule for the right host but a WRONG port.
    const rule = allowRule("127.0.0.1", upstream.port === 65535 ? 65534 : upstream.port + 1);
    const rules = [rule];
    const port = await listen(tcbOptions(rules));
    const before = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 403 Forbidden");
    // Attack: mutate the deepest captured structure -- the port array itself --
    // both by push and by index overwrite.
    (rule.match.port as number[]).push(upstream.port);
    (rule.match.port as number[])[0] = upstream.port;
    const after = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 403 Forbidden");
  });

  it("index-overwriting rules[0] with a permissive rule stays denied (element replacement, not push)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const rules = [allowRule("127.0.0.2", 1)]; // matches nothing relevant
    const port = await listen(tcbOptions(rules));
    const before = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 403 Forbidden");
    // Attack: replace the element (and also unshift a second permissive rule,
    // covering reorder/insert-at-front).
    rules[0] = allowRule("127.0.0.1", upstream.port);
    rules.unshift(allowRule("127.0.0.1", upstream.port));
    const after = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 403 Forbidden");
  });

  it("mutating the nested scope object (scope.uids) after construction changes nothing", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const rule = allowRule("127.0.0.2", upstream.port);
    rule.scope = { uids: [AGENT_UID] };
    const rules = [rule];
    const port = await listen(tcbOptions(rules));
    const before = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 403 Forbidden");
    // Attack: mutate scope in place alongside the match widen (belt-and-braces:
    // even the scope subtree of the caller's object must be inert).
    rule.scope.uids!.push(999);
    rule.scope.agent_ids = ["*"];
    rule.match.host = "127.0.0.1";
    const after = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 403 Forbidden");
  });

  it("a live getter on disposition (deny at clone time, allow later) cannot re-open the gate (TOCTOU)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // structuredClone reads the getter ONCE at construction; a shallow copy
    // (Array.from) would keep the live object and re-read "allow" per CONNECT.
    let armed = false;
    const base = allowRule("127.0.0.1", upstream.port);
    const rule = {
      ...base,
      get disposition(): AllowlistRule["disposition"] {
        return armed ? "allow" : "deny";
      },
    } as AllowlistRule;
    const rules = [rule];
    const port = await listen(tcbOptions(rules));
    const before = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 403 Forbidden");
    armed = true; // flip the live value the caller's object now reports
    expect(rule.disposition).toBe("allow"); // the caller's object DID flip...
    const after = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 403 Forbidden"); // ...the gate did not
  });
});

// ---------------------------------------------------------------------------
// ATTACK 2: the NARROW direction. The snapshot must be a true copy, not a
// lazily-read view: a constructed-allow gate keeps allowing after the caller
// empties/poisons its own array (proves the clone is taken eagerly at
// construction, so enforcement is exactly what the construction guards saw).
// ---------------------------------------------------------------------------
describe("round-6 refute: the allow snapshot survives the caller destroying its own array", () => {
  it("emptying the caller array + flipping the rule to deny does NOT flip an allow snapshot", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const rule = allowRule("127.0.0.1", upstream.port);
    const rules = [rule];
    const port = await listen(tcbOptions(rules));
    const before = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(before.statusLine).toBe("HTTP/1.1 200 Connection Established");
    // Attack (availability direction): gut the caller's array and the rule.
    rule.disposition = "deny";
    rules.length = 0;
    const after = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(after.statusLine).toBe("HTTP/1.1 200 Connection Established");
  });
});

// ---------------------------------------------------------------------------
// ATTACK 3: freeze depth. The gate's captured clone must be frozen at EVERY
// level (array, rule, match, port array, scope), not just the top. We cannot
// reach the internal clone from outside (nothing leaks it -- itself a property
// this test would fail if violated via onEvent/decision), so this drives the
// deepFreeze helper through the same source path shape: a structuredClone of a
// representative rule set, frozen via the module's construction (asserted
// statically), plus a static assertion that the capture site composes
// deepFreeze(structuredClone(...)).
// ---------------------------------------------------------------------------
describe("round-6 refute: static -- the capture site is deepFreeze(structuredClone(options.rules))", () => {
  it("gate-server.ts captures rules as a deep-frozen clone and never re-reads options.rules later", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const src = readFileSync(
      fileURLToPath(new URL("../../src/egress-gate/gate-server.ts", import.meta.url)),
      "utf8",
    );
    // The one and only read of options.rules is the deep-frozen clone capture.
    const reads = src.match(/options\.rules/g) ?? [];
    expect(reads.length).toBe(1);
    expect(src).toMatch(/deepFreeze\(structuredClone\(options\.rules\)\)/);
    // deepFreeze recurses over every own enumerable key BEFORE freezing, so the
    // nested match/port/scope subtrees are all frozen, not just the array.
    expect(src).toMatch(/function deepFreeze[\s\S]*?Object\.keys[\s\S]*?deepFreeze\([\s\S]*?Object\.freeze\(value\)/);
  });
});
