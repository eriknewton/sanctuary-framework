/**
 * INDEPENDENT refute suite (S5-3 review) for fail-closed client auth + the
 * gate-server TCB integration. Every test is an ATTACK; the assertion is that
 * the bypass FAILS (deny). Focus: corners the builder's own suite does not
 * cover — destination-policy bypass under a valid credential, liveness
 * precedence over a valid credential, garbage/empty headers, same-generation
 * wrong secret, and the pure-decision skipped_cap / no_accept_state paths.
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
import {
  createGateClientAuthenticator,
  decideGateClientAuth,
} from "../../src/egress-gate/gate-client-auth.js";
import {
  formatGateCredentialHeader,
  parseGateCredentialHeader,
  verifyGateCredential,
  GATE_CREDENTIAL_VERSION,
  type GateAcceptSource,
  type GateCredentialAcceptRecord,
} from "../../src/egress-gate/gate-credential.js";
import type { PeerCommandRunner } from "../../src/egress-gate/peer-identity.js";
import type { AllowlistRule } from "../../src/castle-wall/allowlist/schema.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../src/castle-wall/constants.js";
import type { PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";

const AGENT_UID = 502;
const GEN = 7;
const SECRET = "deadbeefcafef00d";
const sha256Hex = (v: string): string => createHash("sha256").update(v, "utf8").digest("hex");

const acceptRecord: GateCredentialAcceptRecord = {
  version: GATE_CREDENTIAL_VERSION,
  generation_id: GEN,
  secret_sha256: sha256Hex(SECRET),
};
const acceptSource: GateAcceptSource = { current: () => Promise.resolve(acceptRecord) };
// TCB gates require the oracle-shape probe (coalescing:"forbidden" + a
// policy-matching binding); the gate refuses construction otherwise.
const liveProbe: GateLivenessProbe = {
  coalescing: "forbidden",
  binding: { agentUid: AGENT_UID, gatePort: 19997 },
  check: () => Promise.resolve({ live: true, reasons: [] }),
};
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
      return Promise.resolve({ code: 0, stdout: [`p999`, `u${uid}`, `n127.0.0.1:${clientPort}->127.0.0.1:x`, ""].join("\n") });
    },
  };
}

function startUpstream(): Promise<{ port: number; close: () => void }> {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => socket.end("upstream-hello"));
    server.listen(0, "127.0.0.1", () => resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() }));
  });
}

function rawConnect(gatePort: number, authority: string, proxyAuth?: string): Promise<{ statusLine: string; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(gatePort, "127.0.0.1", () => {
      const authLine = proxyAuth !== undefined ? `Proxy-Authorization: ${proxyAuth}\r\n` : "";
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${authLine}\r\n`);
    });
    let data = "";
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
    socket.on("end", () => resolve({ statusLine: data.split("\r\n")[0] ?? "", body: data.split("\r\n\r\n").slice(1).join("\r\n\r\n") }));
    socket.on("error", reject);
    setTimeout(() => socket.destroy(new Error("test connect timeout")), 5_000).unref();
  });
}

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

async function startTcbGate(overrides: Partial<ExclusiveEgressGateOptions>): Promise<{ port: number; events: EgressGateEvent[] }> {
  const events: EgressGateEvent[] = [];
  const options: ExclusiveEgressGateOptions = {
    policy: { agent_uid: AGENT_UID, gate_port: 19997 },
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

describe("REFUTE gate TCB integration: auth must not bypass destination policy or liveness", () => {
  it("ATTACK valid credential + matched peer to a NON-allowlisted destination — must 403 deny-by-policy, NOT tunnel", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // rules empty => destination is denied even though the client is authorized.
    const { port, events } = await startTcbGate({ rules: [] });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(result.body).not.toContain("upstream-hello");
    // client auth passed (no client_denied) but destination policy still denied.
    expect(events.some((e) => e.kind === "client_denied")).toBe(false);
    const decision = events.find((e) => e.kind === "decision");
    expect(decision && decision.kind === "decision" && decision.decision.disposition).toBe("deny");
  });

  it("ATTACK valid credential + matched peer but liveness DEAD — must 503, never tunnel", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const deadProbe: GateLivenessProbe = {
      coalescing: "forbidden",
      binding: { agentUid: AGENT_UID, gatePort: 19997 },
      check: () => Promise.resolve({ live: false, reasons: ["pf anchor flushed"] }),
    };
    const { port } = await startTcbGate({ rules: [allowRule("127.0.0.1", upstream.port)], livenessProbe: deadProbe });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 503 Service Unavailable");
    expect(result.body).not.toContain("upstream-hello");
  });

  it("ATTACK same-generation WRONG secret — must 403 bad_secret", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startTcbGate({ rules: [allowRule("127.0.0.1", upstream.port)] });
    const wrong = formatGateCredentialHeader({ generation_id: GEN, secret: "0000000000000000" });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, wrong);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("bad_secret");
  });

  it("ATTACK empty Proxy-Authorization header value — must 403 (malformed/no_credential), not tunnel", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port } = await startTcbGate({ rules: [allowRule("127.0.0.1", upstream.port)] });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, "   ");
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(result.body).not.toContain("upstream-hello");
  });

  it("ATTACK scheme-only garbage header ('Sanctuary-Gate garbage') — must 403", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port, events } = await startTcbGate({ rules: [allowRule("127.0.0.1", upstream.port)] });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, "Sanctuary-Gate not-a-valid-token");
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("malformed_credential");
  });

  it("ATTACK Basic-auth style header (wrong scheme) — must 403 malformed", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { port } = await startTcbGate({ rules: [allowRule("127.0.0.1", upstream.port)] });
    const result = await rawConnect(port, `127.0.0.1:${upstream.port}`, "Basic dXNlcjpwYXNz");
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(result.body).not.toContain("upstream-hello");
  });
});

describe("REFUTE pure decision: bearer never overrides peer; accept-state gates hard", () => {
  it("skipped_cap peer with a VALID credential still denies (fail-closed under saturation)", () => {
    const d = decideGateClientAuth({
      agentUid: AGENT_UID,
      peer: { kind: "skipped_cap" },
      credential: { ok: true },
    });
    expect(d.allow).toBe(false);
    expect(!d.allow && d.reason).toBe("peer_unresolved");
  });

  it("resolved+matched peer with NO credential still denies (peer alone cannot authorize)", () => {
    const d = decideGateClientAuth({
      agentUid: AGENT_UID,
      peer: { kind: "resolved", uid: AGENT_UID, pid: 1234 },
      credential: { ok: false, reason: "no_credential" },
    });
    expect(d.allow).toBe(false);
  });

  it("no accept-state (unprotected) => verifyGateCredential denies even with a well-formed presented cred", () => {
    const v = verifyGateCredential(null, { generation_id: GEN, secret: SECRET });
    expect(v.ok).toBe(false);
    expect(!v.ok && v.reason).toBe("no_accept_state");
  });

  it("parse rejects uppercase-hex, whitespace, missing-dot, and trailing-dot headers", () => {
    expect(parseGateCredentialHeader("Sanctuary-Gate 7.DEADBEEF")).toBeNull(); // uppercase
    expect(parseGateCredentialHeader("Sanctuary-Gate 7deadbeef")).toBeNull(); // no dot
    expect(parseGateCredentialHeader("Sanctuary-Gate 7.")).toBeNull(); // empty secret
    expect(parseGateCredentialHeader("Sanctuary-Gate .deadbeef")).toBeNull(); // empty gen
    expect(parseGateCredentialHeader(["Sanctuary-Gate 7.deadbeef", "x"])).toBeNull(); // array/dup
    expect(parseGateCredentialHeader(undefined)).toBeNull();
  });

  it("verifyGateCredential is robust to a stored hash of wrong length (defensive guard, no throw)", () => {
    const badAccept: GateCredentialAcceptRecord = { version: GATE_CREDENTIAL_VERSION, generation_id: GEN, secret_sha256: "abcd" };
    const v = verifyGateCredential(badAccept, { generation_id: GEN, secret: SECRET });
    expect(v.ok).toBe(false);
    expect(!v.ok && v.reason).toBe("bad_secret");
  });
});
