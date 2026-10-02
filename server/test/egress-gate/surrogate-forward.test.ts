/** Capability: authenticated forward swaps, request refusals and isolated TLS transport. */
import { randomBytes } from "node:crypto";
import https from "node:https";
import http from "node:http";
import net from "node:net";
import { EventEmitter } from "node:events";
import type { ClientRequest } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createExclusiveEgressGate, type SurrogateUpstreamRequest } from "../../src/egress-gate/gate-server.js";
import * as helperClientModule from "../../src/egress-gate/surrogate-helper-client.js";
import { createSurrogateHelperClient } from "../../src/egress-gate/surrogate-helper-client.js";
import { SURROGATE_UPSTREAM_CONNECT_DEADLINE_MS, MAX_PLACEHOLDERS_PER_REQUEST, MAX_SURROGATE_HEADER_NAME_LENGTH, mintSurrogatePlaceholder } from "../../src/credential-surrogate/index.js";
import { clean, directory, binding, helper, tlsUpstream, daemon, direct, raw, request, listen, HOST, UID } from "./surrogate-forward-fixture.js";

afterEach(clean);

describe("wired surrogate forward consumer", () => {
  it("daemon and real unlocked helper replace only the bound header and join helper events", async () => {
    const dir = await directory(); const b = binding(); const h = await helper(dir, [b]);
    const value = randomBytes(20).toString("hex"); await h.unlock(b, value);
    const upstream = await tlsUpstream(dir); const gate = await daemon(dir, { upstreamRequest: upstream.dial });
    const response = await raw(gate.port, request(gate.header, `Authorization: Bearer ${b.placeholder}\r\nAccept-Encoding: gzip\r\nContent-Length: 3\r\n`) + "abc");
    expect(response).toContain("200 OK");
    expect(upstream.received.length).toBe(1);
    expect(upstream.received[0]!.headers.authorization === `Bearer ${value}`).toBe(true);
    expect(upstream.received[0]!.headers["accept-encoding"]).toBe("identity");
    expect(upstream.received[0]!.headers["proxy-authorization"]).toBeUndefined();
    expect(upstream.received[0]!.headers["content-length"]).toBe("3");
    expect(upstream.received[0]!.body.toString()).toBe("abc");
    const swap = gate.events.find(e => e.kind === "surrogate_swap");
    const answer = h.events.find(e => e.kind === "query_answered");
    expect(swap?.kind === "surrogate_swap" && answer?.kind === "query_answered" && swap.correlationId === answer.correlationId).toBe(true);
    expect(answer?.kind === "query_answered" && answer.binding).toBe(b.ordinal);
    const logs = JSON.stringify([...gate.events, ...h.events]);
    expect(logs.includes(value)).toBe(false); expect(logs.includes(b.placeholder)).toBe(false); expect(logs.includes('"message"')).toBe(false);
    expect(upstream.dial.mock.calls[0]![0]).toMatchObject({ hostname: "203.0.113.1", port: 443, servername: HOST, rejectUnauthorized: true, agent: false });
  });
  it.each(["misroute", "wrong_header", "target", "unknown"])("refuses %s before DNS and dial", async mode => {
    const dir = await directory(); const b = binding(); const h = await helper(dir, [b]); await h.unlock(b, randomBytes(20).toString("hex"));
    const dial = vi.fn<SurrogateUpstreamRequest>(() => { throw new Error("unexpected dial"); });
    const gate = await daemon(dir, { upstreamRequest: dial });
    let wire = request(gate.header, `Authorization: ${mode === "unknown" ? mintSurrogatePlaceholder() : b.placeholder}\r\n`);
    if (mode === "wrong_header") wire = request(gate.header, `X-Other: ${b.placeholder}\r\n`);
    if (mode === "target") wire = request(gate.header, "", `http://${HOST}/${b.placeholder}`);
    if (mode === "misroute") wire = wire.replaceAll(HOST, "other.example.test");
    expect(await raw(gate.port, wire)).toContain("403 Forbidden");
    expect(gate.resolver.resolve).not.toHaveBeenCalled(); expect(dial).not.toHaveBeenCalled();
    const denial = gate.events.find(e => e.kind === "surrogate_denied");
    expect(denial?.kind === "surrogate_denied" && denial.reason).toBe(mode === "misroute" ? "misroute" : mode === "unknown" ? "unknown" : "wrong_location");
    const helperDenial = h.events.find(e => e.kind === "query_denied");
    expect(denial?.kind === "surrogate_denied" && helperDenial?.kind === "query_denied" && denial.correlationId === helperDenial.correlationId).toBe(true);
  });
  it.each(["locked", "absent"])("degrades %s helper with no resolver or dial", async mode => {
    const dir = await directory(); const b = binding(); if (mode === "locked") await helper(dir, [b]);
    const dial = vi.fn<SurrogateUpstreamRequest>(); const gate = await daemon(dir, { upstreamRequest: dial });
    const result = await raw(gate.port, request(gate.header, `Authorization: ${b.placeholder}\r\n`));
    expect(result).toContain("503 Service Unavailable"); expect(result).toContain(mode === "locked" ? "surrogate-locked" : "surrogate-helper-unavailable");
    expect(gate.resolver.resolve).not.toHaveBeenCalled(); expect(dial).not.toHaveBeenCalled();
    if (mode === "absent") expect(gate.events.some(e => e.kind === "surrogate_helper_unavailable" && e.correlationId === undefined)).toBe(true);
  });
  it.each([null, 8])("keeps the original 405 with absent or stale destinations %s", async generation => {
    const dir = await directory(); const dial = vi.fn<SurrogateUpstreamRequest>();
    const gate = await daemon(dir, { upstreamRequest: dial }, generation);
    const response = await raw(gate.port, request(gate.header));
    const old = await direct(); const prior = await raw(old.port, request(old.header));
    const withoutDate = (s: string) => s.replace(/Date: [^\r]+\r\n/, "");
    expect(withoutDate(response)).toBe(withoutDate(prior));
    expect(dial).not.toHaveBeenCalled(); expect(gate.resolver.resolve).not.toHaveBeenCalled();
  });
  it("redacts CONNECT authority at the daemon sink", async () => {
    const dir = await directory(); const gate = await daemon(dir); const p = mintSurrogatePlaceholder();
    await raw(gate.port, `CONNECT ${p}:443 HTTP/1.1\r\nHost: ${p}:443\r\nProxy-Authorization: ${gate.header}\r\n\r\n`);
    expect(JSON.stringify(gate.events).includes(p)).toBe(false);
    expect(JSON.stringify(gate.events)).toContain("<surrogate-placeholder>");
  });
});

describe("forward refusals", () => {
  it("refuses each missing construction dependency", async () => {
    const gate = await direct();
    const f = { destinations: [`${HOST}:443`], helperClient: createSurrogateHelperClient(UID, await directory()) };
    expect(() => createExclusiveEgressGate({ ...gate.defaults, forwardMode: f, clientAuth: undefined })).toThrow();
    expect(() => createExclusiveEgressGate({ ...gate.defaults, forwardMode: { ...f, helperClient: undefined! } })).toThrow();
    expect(() => createExclusiveEgressGate({ ...gate.defaults, forwardMode: f, livenessProbe: { check: async () => ({ live: true, reasons: [] }) } })).toThrow();
  });
  it.each([
    ["Host: elsewhere.test\r\n", 400, "surrogate-host-mismatch"],
    ["Authorization: a\r\nAUTHORIZATION: b\r\n", 400, "surrogate-duplicate-header"],
    ["Content-Length: 0\r\nContent-Length: 0\r\n", 400, "surrogate-duplicate-header"],
    ["Host: api.example.test\r\n", 400, "surrogate-duplicate-header"],
    ["Transfer-Encoding: chunked\r\n", 411, "surrogate-transfer-encoding"],
    ["Upgrade: websocket\r\n", 501, "surrogate-upgrade"],
  ] as const)("refuses request shape before helper and resolver (%s)", async (fields, status, code) => {
    const query = vi.fn(); const gate = await direct({ forwardMode: { destinations: [`${HOST}:443`], helperClient: { query } } });
    let wire = request(gate.header, fields);
    if (code === "surrogate-host-mismatch") wire = wire.replace(`Host: ${HOST}\r\n`, "");
    const result = await raw(gate.port, wire);
    expect(result).toContain(` ${status} `); expect(result).toContain(code); expect(query).not.toHaveBeenCalled(); expect(gate.resolver.resolve).not.toHaveBeenCalled();
  });
  it.each(["https://api.example.test/", "http://a@api.example.test/", "http://127.0.0.1/", "http://api.example.test:81/"])("refuses target %s before helper", async target => {
    const query = vi.fn(); const gate = await direct({ forwardMode: { destinations: [], helperClient: { query } } });
    expect(await raw(gate.port, request(gate.header, "", target))).toContain("400 Bad Request"); expect(query).not.toHaveBeenCalled(); expect(gate.resolver.resolve).not.toHaveBeenCalled();
  });
  it("refuses 10000 over-cap requests without one queued query", async () => {
    const query = vi.fn(); const gate = await direct({ forwardMode: { destinations: [], helperClient: { query } } });
    const fields = `Authorization: ${Array.from({ length: MAX_PLACEHOLDERS_PER_REQUEST + 1 }, () => mintSurrogatePlaceholder()).join(" ")}\r\n`;
    for (let i = 0; i < 10_000; i++) {
      const response = await raw(gate.port, request(gate.header, fields));
      expect(response.includes("403 Forbidden") && response.includes("surrogate-limit")).toBe(true);
    }
    expect(query).not.toHaveBeenCalled(); expect(gate.resolver.resolve).not.toHaveBeenCalled();
  }, 120_000);
  it("header-write throws return a fixed 502 with no error text and no retry", async () => {
    const dir = await directory(); const b = binding(); const h = await helper(dir, [b]); const value = randomBytes(20).toString("hex"); await h.unlock(b, value);
    const dial = vi.fn<SurrogateUpstreamRequest>(() => { throw new Error(value); }); const gate = await daemon(dir, { upstreamRequest: dial });
    expect(await raw(gate.port, request(gate.header, `Authorization: ${b.placeholder}\r\n`))).toContain("header_write_failed");
    expect(dial).toHaveBeenCalledTimes(1); expect(JSON.stringify(gate.events).includes(value)).toBe(false); expect(JSON.stringify(gate.events).includes('"message"')).toBe(false);
  });
  it("certificate identity mismatch sends zero HTTP header bytes", async () => {
    const dir = await directory(); const upstream = await tlsUpstream(dir, "other.example.test");
    const b = binding(); const h = await helper(dir, [b]); await h.unlock(b, randomBytes(20).toString("hex"));
    const gate = await daemon(dir, { upstreamRequest: upstream.dial });
    expect(await raw(gate.port, request(gate.header, `Authorization: ${b.placeholder}\r\n`))).toContain("upstream_tls_failed");
    expect(upstream.received).toHaveLength(0);
  });
  it("stalled TCP-to-TLS handshake expires before any header bytes", async () => {
    let bytes = 0;
    const stalled = net.createServer(socket => { socket.on("data", c => { bytes += c.length; }); });
    const port = await listen(stalled);
    const dial: SurrogateUpstreamRequest = (options, listener) => https.request({ ...options, hostname: "127.0.0.1", port }, listener);
    const gate = await daemon(await directory(), { upstreamRequest: dial });
    const begin = Date.now(); const result = await raw(gate.port, request(gate.header));
    expect(result).toContain("502 Bad Gateway"); expect(result).toContain("upstream_tls_failed");
    expect(Date.now() - begin).toBeGreaterThanOrEqual(SURROGATE_UPSTREAM_CONNECT_DEADLINE_MS);
    expect(Date.now() - begin).toBeLessThan(SURROGATE_UPSTREAM_CONNECT_DEADLINE_MS + 2_000);
    expect(bytes > 0).toBe(true);
  }, 10_000);
});

describe("forward stream and per-request authority", () => {
  it("rejects body byte-count mismatch at the streaming consumer", async () => {
    const dir = await directory(); const upstream = await tlsUpstream(dir);
    const gate = await direct({ upstreamRequest: upstream.dial, forwardMode: { destinations: [`${HOST}:443`], helperClient: { query: vi.fn() } } });
    // Fault injection beneath the parsed length exercises the forwarding byte counter.
    gate.server.on("request", incoming => { incoming.unshift(Buffer.from("extra")); });
    const result = await raw(gate.port, request(gate.header, "Content-Length: 1\r\n") + "a");
    expect(result).toContain("body_length_mismatch");
    expect(upstream.received).toHaveLength(0);
  });
  it("denies liveness and authorization before helper work on every request", async () => {
    const query = vi.fn(); let live = false; let allowed = true;
    const check = vi.fn(async () => ({ live, reasons: [] }));
    const authorize = vi.fn(async () => allowed ? { allow: true as const, peerUid: UID } : { allow: false as const, reason: "peer_unresolved" as const });
    const gate = await direct({ livenessProbe: { coalescing: "forbidden", binding: { agentUid: UID, gatePort: 19998 }, check }, clientAuth: { agentUid: UID, authorize }, forwardMode: { destinations: [], helperClient: { query } } });
    expect(await raw(gate.port, request(gate.header))).toContain("503 Service Unavailable");
    expect(authorize).not.toHaveBeenCalled(); live = true; allowed = false;
    expect(await raw(gate.port, request(gate.header))).toContain("403 Forbidden");
    expect(check).toHaveBeenCalledTimes(2); expect(authorize).toHaveBeenCalledTimes(1); expect(query).not.toHaveBeenCalled();
  });
  it("keeps unbound no-placeholder requests on the 405 path", async () => {
    const gate = await daemon(await directory());
    expect(await raw(gate.port, request(gate.header).replaceAll(HOST, "other.example.test"))).toContain("405 Method Not Allowed");
    expect(gate.resolver.resolve).not.toHaveBeenCalled();
  });
});


describe("late TLS completion", () => {
  it("a secureConnect delivered after the connect deadline never writes or ends headers", async () => {
    const socket = new EventEmitter() as EventEmitter & { authorized: boolean };
    socket.authorized = true;
    const outgoing = Object.assign(new EventEmitter(), { destroy: vi.fn(), write: vi.fn(), end: vi.fn() });
    const dial: SurrogateUpstreamRequest = () => {
      queueMicrotask(() => outgoing.emit("socket", socket));
      return outgoing as unknown as ClientRequest;
    };
    const gate = await daemon(await directory(), { upstreamRequest: dial });
    const response = await raw(gate.port, request(gate.header));
    expect(response).toContain("502 Bad Gateway");
    socket.emit("secureConnect");
    await new Promise<void>(r => setImmediate(r));
    expect(outgoing.destroy).toHaveBeenCalled();
    expect(outgoing.listenerCount("drain")).toBe(0);
    expect(outgoing.write).not.toHaveBeenCalled(); expect(outgoing.end).not.toHaveBeenCalled();
  }, 10_000);
});


it("absent destinations never construct a helper client", async () => {
  const construct = vi.spyOn(helperClientModule, "createSurrogateHelperClient");
  try {
    const gate = await daemon(await directory(), {}, null);
    expect(await raw(gate.port, request(gate.header))).toContain("405 Method Not Allowed");
    expect(construct).not.toHaveBeenCalled();
  } finally { construct.mockRestore(); }
});


it("refuses an unrepresentable header location before issuing a query", async () => {
  const query = vi.fn(); const gate = await direct({ forwardMode: { destinations: [], helperClient: { query } } });
  const result = await raw(gate.port, request(gate.header, `${"x".repeat(MAX_SURROGATE_HEADER_NAME_LENGTH + 1)}: ${mintSurrogatePlaceholder()}\r\n`));
  expect(result).toContain("403 Forbidden"); expect(result).toContain("surrogate-wrong-location");
  expect(query).not.toHaveBeenCalled(); expect(gate.resolver.resolve).not.toHaveBeenCalled();
});

it("handles the real HTTP upgrade event with a 501", async () => {
  const query = vi.fn(); const gate = await direct({ forwardMode: { destinations: [], helperClient: { query } } });
  const wire = request(gate.header, "Upgrade: websocket\r\n").replace("Connection: close", "Connection: Upgrade");
  const socket = net.connect(gate.port, "127.0.0.1", () => socket.write(wire));
  let response = "";
  socket.on("data", chunk => { response += chunk.toString(); });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const closed = await new Promise<boolean>(resolve => {
      socket.on("close", () => resolve(true));
      // Half a second allows local FIN delivery while exposing a response with no socket owner.
      timer = setTimeout(() => resolve(false), 500);
    });
    expect(response).toContain("501 Not Implemented"); expect(closed).toBe(true);
    expect(query).not.toHaveBeenCalled();
  } finally { clearTimeout(timer); socket.destroy(); }
});

it("concurrent requests carry only their own binding values through the real object graph", async () => {
  const dir = await directory(); const a = binding(1); const b = binding(2); const h = await helper(dir, [a, b]);
  const values = [randomBytes(20).toString("hex"), randomBytes(20).toString("hex")];
  await h.unlock(a, values[0]!); await h.unlock(b, values[1]!);
  const upstream = await tlsUpstream(dir); const gate = await daemon(dir, { upstreamRequest: upstream.dial });
  const responses = await Promise.all([a, b].map((bound, index) => raw(gate.port, request(gate.header, `Authorization: ${bound.placeholder}\r\n`, `http://${HOST}/${index}`))));
  expect(responses.every(r => r.includes("200 OK"))).toBe(true); expect(upstream.received).toHaveLength(2);
  expect(upstream.received.every(r => r.headers.authorization === values[Number(r.url.slice(1))])).toBe(true);
});


it("repeated no-placeholder 405 requests do not retain per-request socket listeners", async () => {
  const query = vi.fn(); const gate = await direct({ forwardMode: { destinations: [], helperClient: { query } } });
  const sockets: net.Socket[] = [];
  gate.server.on("connection", socket => sockets.push(socket));
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  const send = () => new Promise<void>((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port: gate.port, path: `http://${HOST}/`, agent, headers: { host: HOST, "proxy-authorization": gate.header } }, response => {
      response.resume(); response.on("end", () => { expect(response.statusCode).toBe(405); resolve(); });
    });
    req.on("error", reject); req.end();
  });
  try {
    await send(); const listeners = sockets[0]!.listenerCount("error");
    // Thirty-two reuse waves expose retained request closures beyond EventEmitter's warning threshold.
    for (let wave = 0; wave < 32; wave++) await send();
    expect(sockets).toHaveLength(1);
    expect(sockets[0]!.listenerCount("error")).toBe(listeners);
    expect(query).not.toHaveBeenCalled();
  } finally { agent.destroy(); }
});

it("forward mode preserves native malformed CONNECT response bytes", async () => {
  const prior = await direct();
  const forward = await direct({ forwardMode: { destinations: [], helperClient: { query: vi.fn() } } });
  const wire = `CONNECT ${HOST}:443 HTTP/1.1\r\nHost: ${HOST}:443\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n`;
  const expected = await raw(prior.port, wire);
  expect(expected).toContain("400 Bad Request");
  expect(await raw(forward.port, wire)).toBe(expected);
});
