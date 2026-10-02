/** Capability: bounded forwarding and joinable terminal events under transport faults. */
import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import net from "node:net";
import https from "node:https";
import type { IncomingMessage } from "node:http";
import { afterEach, expect, it, vi } from "vitest";
import { surrogateDestinationsPath } from "../../src/egress-gate/surrogate-helper-daemon.js";
import { type SurrogateUpstreamRequest, type SurrogateGateEvent } from "../../src/egress-gate/gate-server.js";
import { SURROGATE_UPSTREAM_CONNECT_DEADLINE_MS } from "../../src/credential-surrogate/index.js";
import { clean, cleanup, directory, binding, helper, tlsUpstream, daemon, direct, raw, request, listen, HOST, UID } from "./surrogate-forward-fixture.js";

afterEach(clean);

it("joins every helper query when the client disconnects before helper connect", async () => {
  const dir = await directory(); const b = binding(); const h = await helper(dir, [b]);
  await h.unlock(b, randomBytes(20).toString("hex"));
  const dial = vi.fn<SurrogateUpstreamRequest>(); const gate = await daemon(dir, { upstreamRequest: dial });
  let release!: () => void;
  let connected!: () => void; const pendingConnect = new Promise<void>(r => { connected = r; });
  const realEmit = net.Socket.prototype.emit;
  const emitSpy = vi.spyOn(net.Socket.prototype, "emit").mockImplementation(function (this: net.Socket, event, ...values) {
    if (event !== "connect" || this.remoteAddress !== undefined) return realEmit.call(this, event, ...values);
    // The only outbound Unix socket after unlock is the real helper query; TCP client events pass through.
    const helperSocket = this;
    release = () => { emitSpy.mockRestore(); realEmit.call(helperSocket, event, ...values); };
    cleanup.push(async () => { helperSocket.destroy(); });
    connected();
    return true;
  });
  cleanup.push(async () => { emitSpy.mockRestore(); });
  const socket = net.connect(gate.port, "127.0.0.1", () => socket.write(request(gate.header, `Authorization: ${b.placeholder}\r\n`)));
  socket.on("error", () => {}); cleanup.push(async () => { socket.destroy(); });
  await pendingConnect;
  expect(h.events.some(e => e.kind === "query_answered" || e.kind === "query_denied")).toBe(false);
  socket.destroy();
  await vi.waitFor(() => expect(gate.events.some(e => e.kind === "surrogate_denied" && e.code === "socket_error")).toBe(true));
  release();
  await vi.waitFor(() => expect(h.events.some(e => e.kind === "query_answered")).toBe(true));
  const queries = h.events.filter(e => e.kind === "query_answered" || e.kind === "query_denied");
  expect(queries).toHaveLength(1);
  for (const query of queries) {
    expect(query.correlationId).toBeDefined();
    expect(gate.events.some(e => e.kind === "surrogate_denied" && e.code === "socket_error" && e.correlationId === query.correlationId)).toBe(true);
  }
  expect(gate.events.some(e => e.kind === "surrogate_swap")).toBe(false);
  expect(gate.resolver.resolve).not.toHaveBeenCalled(); expect(dial).not.toHaveBeenCalled();
});

it("records successful swap completion status and body byte counts for every query", async () => {
  const dir = await directory(); const bindings = [binding(), binding(2, "X-Api-Key")];
  const h = await helper(dir, bindings);
  for (const b of bindings) await h.unlock(b, randomBytes(20).toString("hex"));
  const upstream = await tlsUpstream(dir);
  const body = "request \u00e9"; const reply = "response \u2603";
  upstream.server.removeAllListeners("request");
  upstream.server.on("request", (incoming, response) => {
    const chunks: Buffer[] = []; incoming.on("data", c => chunks.push(c));
    incoming.on("end", () => {
      expect(Buffer.concat(chunks).toString()).toBe(body);
      response.writeHead(201, { "Content-Length": Buffer.byteLength(reply) });
      response.write(reply.slice(0, -1)); response.end(reply.slice(-1));
    });
  });
  const gate = await daemon(dir, { upstreamRequest: upstream.dial });
  const result = await raw(gate.port, request(gate.header,
    `Authorization: ${bindings[0]!.placeholder}\r\nX-Api-Key: ${bindings[1]!.placeholder}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n`) + body);
  expect(result).toContain("201 Created"); expect(result).toContain(reply);
  const ids = h.events.filter(e => e.kind === "query_answered").map(e => e.correlationId).sort();
  expect(ids).toHaveLength(bindings.length);
  const swaps = gate.events.filter((e): e is SurrogateGateEvent => e.kind === "surrogate_swap");
  const commits = swaps.filter(e => e.status === 0);
  const completed = swaps.filter(e => e.status === 201);
  expect(commits.map(e => e.correlationId).sort()).toEqual(ids);
  expect(completed.map(e => e.correlationId).sort()).toEqual(ids);
  for (const event of completed) {
    expect(event.requestBytes).toBe(Buffer.byteLength(body));
    expect(event.responseBytes).toBe(Buffer.byteLength(reply));
    expect(gate.events.indexOf(event)).toBeGreaterThan(gate.events.indexOf(commits.at(-1)!));
  }
  expect(gate.events.some(e => e.kind === "surrogate_denied")).toBe(false);
});

it.each(["reset", "disconnect", "policy", "response_reset"])("joins every answered query on %s and records commitment before response", async mode => {
  const dir = await directory(); const bindings = [binding(), binding(2, "X-Api-Key")];
  const h = await helper(dir, bindings);
  for (const b of bindings) await h.unlock(b, randomBytes(20).toString("hex"));
  const upstream = await tlsUpstream(dir);
  let observed!: () => void; const received = new Promise<void>(r => { observed = r; });
  upstream.server.removeAllListeners("request");
  upstream.server.on("request", incoming => { incoming.resume(); incoming.on("end", () => { observed(); if (mode === "reset") incoming.socket.destroy();
      if (mode === "response_reset") incoming.socket.write("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\na", () => incoming.socket.destroy()); }); });
  const gate = await daemon(dir, { upstreamRequest: upstream.dial, ...(mode === "policy" ? { loadRules: async () => [] } : {}) });
  const wire = request(gate.header, `Authorization: ${bindings[0]!.placeholder}\r\nX-Api-Key: ${bindings[1]!.placeholder}\r\n`);
  if (mode === "disconnect") {
    const socket = net.connect(gate.port, "127.0.0.1", () => socket.write(wire)); socket.on("error", () => {});
    cleanup.push(async () => { socket.destroy(); });
    await received;
    expect(gate.events.filter((e): e is SurrogateGateEvent => e.kind === "surrogate_swap")).toHaveLength(2);
    socket.destroy();
    await vi.waitFor(() => expect(gate.events.filter((e): e is SurrogateGateEvent => e.kind === "surrogate_denied")).toHaveLength(2));
  } else {
    const response = await raw(gate.port, wire);
    if (mode !== "response_reset") expect(response).toContain(mode === "policy" ? "403 Forbidden" : "502 Bad Gateway");
  }
  const ids = h.events.filter(e => e.kind === "query_answered").map(e => e.correlationId).sort();
  expect(ids).toHaveLength(2);
  const denied = gate.events.filter((e): e is SurrogateGateEvent => e.kind === "surrogate_denied");
  expect(denied.map(e => e.correlationId).sort()).toEqual(ids);
  const swaps = gate.events.filter((e): e is SurrogateGateEvent => e.kind === "surrogate_swap");
  expect(swaps.map(e => e.correlationId).sort()).toEqual(mode === "policy" ? [] : ids);
  if (mode !== "policy") expect(gate.events.indexOf(swaps[1]!)).toBeLessThan(gate.events.indexOf(denied[0]!));
  else { expect(gate.resolver.resolve).not.toHaveBeenCalled(); expect(upstream.dial).not.toHaveBeenCalled(); }
});

it("bounds pipelined admission while the first liveness check is pending", async () => {
  let release!: () => void;
  const pending = new Promise<void>(r => { release = r; });
  const check = vi.fn(async () => { await pending; return { live: true, reasons: [] }; });
  const query = vi.fn();
  const gate = await direct({ livenessProbe: { coalescing: "forbidden", binding: { agentUid: UID, gatePort: 19998 }, check }, forwardMode: { destinations: [], helperClient: { query } } });
  // Ten thousand requests on one socket must not allocate ten thousand asynchronous handlers.
  const wire = request(gate.header).replace("Connection: close", "Connection: keep-alive").repeat(10_000);
  const socket = net.connect(gate.port, "127.0.0.1", () => socket.write(wire)); socket.on("error", () => {}); socket.resume();
  cleanup.push(async () => { release(); socket.destroy(); });
  await vi.waitFor(() => expect(check).toHaveBeenCalled());
  await new Promise(r => setTimeout(r, 100));
  expect(check).toHaveBeenCalledTimes(1);
  expect(query).not.toHaveBeenCalled();
  expect(gate.events.some(e => e.kind === "surrogate_denied" && e.code === "limit")).toBe(true);
  release();
  await new Promise(r => setImmediate(r));
  expect(gate.resolver.resolve).not.toHaveBeenCalled();
});

it("contains an invalid upstream status in the response callback", async () => {
  const dir = await directory(); const b = binding(); const h = await helper(dir, [b]); await h.unlock(b, randomBytes(20).toString("hex"));
  const upstream = await tlsUpstream(dir);
  let escaped = false;
  const dial: SurrogateUpstreamRequest = (options, listener) => upstream.dial(options, incoming => {
    incoming.statusCode = 0;
    try { listener(incoming); } catch { escaped = true; incoming.destroy(); }
  });
  const gate = await daemon(dir, { upstreamRequest: dial });
  let response = "";
  const socket = net.connect(gate.port, "127.0.0.1", () => socket.write(request(gate.header, `Authorization: ${b.placeholder}\r\n`)));
  socket.on("data", c => { response += c.toString(); }); socket.on("error", () => {});
  cleanup.push(async () => { socket.destroy(); });
  await vi.waitFor(() => expect(escaped || response.includes("502 Bad Gateway")).toBe(true));
  expect(escaped).toBe(false);
  expect(response).toContain("upstream_reset");
  const id = h.events.find(e => e.kind === "query_answered")?.correlationId;
  expect(gate.events.some(e => e.kind === "surrogate_denied" && e.correlationId === id && e.code === "upstream_reset")).toBe(true);
});

it.each(["malformed", "unreadable"])("refuses %s destinations loudly", async mode => {
  const dir = await directory(); const path = surrogateDestinationsPath(UID, dir);
  if (mode === "malformed") await writeFile(path, "invalid-json"); else await mkdir(path);
  const dial = vi.fn<SurrogateUpstreamRequest>();
  const gate = await daemon(dir, { upstreamRequest: dial }, null);
  expect(await raw(gate.port, request(gate.header))).toContain("surrogate-destinations-unavailable");
  expect(gate.events.some(e => e.kind === "surrogate_denied" && e.code === "destinations_unavailable" && e.status === 503)).toBe(true);
  expect(gate.resolver.resolve).not.toHaveBeenCalled(); expect(dial).not.toHaveBeenCalled();
});

it("real TLS completion after refusal never commits HTTP headers", async () => {
  const dir = await directory(); const material = await tlsUpstream(dir);
  let release!: () => void;
  let arrived!: () => void; const hello = new Promise<void>(r => { arrived = r; });
  const { createSecureContext } = await import("node:tls");
  const context = createSecureContext({ key: material.key, cert: material.cert });
  const server = https.createServer({ key: material.key, cert: material.cert, SNICallback: (_name, done) => { release = () => done(null, context); arrived(); } });
  const received = vi.fn((_req: IncomingMessage, res: import("node:http").ServerResponse) => res.end());
  server.on("request", received); const port = await listen(server);
  let completed = false;
  const dial: SurrogateUpstreamRequest = (options, listener) => {
    const outgoing = https.request({ ...options, hostname: "127.0.0.1", port, ca: material.cert }, listener);
    outgoing.on("socket", socket => socket.on("secureConnect", () => { completed = true; }));
    cleanup.push(async () => { outgoing.destroy(); });
    return outgoing;
  };
  const gate = await direct({ upstreamRequest: dial, forwardMode: { destinations: [`${HOST}:443`], helperClient: { query: vi.fn() } } });
  let incoming!: IncomingMessage; gate.server.on("request", req => { incoming = req; });
  const result = raw(gate.port, request(gate.header));
  await hello;
  expect(await result).toContain("upstream_tls_failed");
  release();
  // Re-deliver request completion after the delayed real TLS handshake, exposing any resumed body consumer.
  await new Promise(r => setTimeout(r, 100));
  incoming.emit("end");
  await new Promise(r => setTimeout(r, 100));
  expect(received.mock.calls.length).toBe(0);
  expect(completed).toBe(false);
}, SURROGATE_UPSTREAM_CONNECT_DEADLINE_MS + 5_000);


it("a later helper denial preserves the earlier answer and the denied query", async () => {
  const dir = await directory(); const a = binding(); const b = binding(2, "X-Api-Key"); const h = await helper(dir, [a, b]);
  await h.unlock(a, randomBytes(20).toString("hex"));
  const dial = vi.fn<SurrogateUpstreamRequest>(); const gate = await daemon(dir, { upstreamRequest: dial });
  expect(await raw(gate.port, request(gate.header, `Authorization: ${a.placeholder}\r\nX-Api-Key: ${b.placeholder}\r\n`))).toContain("503 Service Unavailable");
  const ids = h.events.filter(e => e.kind === "query_answered" || e.kind === "query_denied").map(e => e.correlationId).sort();
  expect(ids).toHaveLength(2);
  expect(gate.events.filter((e): e is SurrogateGateEvent => e.kind === "surrogate_denied").map(e => e.correlationId).sort()).toEqual(ids);
  expect(dial).not.toHaveBeenCalled(); expect(gate.resolver.resolve).not.toHaveBeenCalled();
});

it("upstream handshake timeout retains the answered query without a commit event", async () => {
  const dir = await directory(); const b = binding(); const h = await helper(dir, [b]); await h.unlock(b, randomBytes(20).toString("hex"));
  const stalled = net.createServer(socket => socket.resume()); const port = await listen(stalled);
  const dial: SurrogateUpstreamRequest = (options, listener) => https.request({ ...options, hostname: "127.0.0.1", port }, listener);
  const gate = await daemon(dir, { upstreamRequest: dial });
  expect(await raw(gate.port, request(gate.header, `Authorization: ${b.placeholder}\r\n`))).toContain("upstream_tls_failed");
  const id = h.events.find(e => e.kind === "query_answered")?.correlationId;
  expect(id).toBeDefined();
  expect(gate.events.some(e => e.kind === "surrogate_denied" && e.code === "upstream_tls_failed" && e.correlationId === id)).toBe(true);
  expect(gate.events.some(e => e.kind === "surrogate_swap")).toBe(false);
}, SURROGATE_UPSTREAM_CONNECT_DEADLINE_MS + 5_000);
