/** Capability: swapped forward responses use the bounded echo guard through the daemon. SURROGATE-1B-II-CLAUDE-F1 SURROGATE-1B-II-LENIENT-PREFIX */
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runSecretsCommand } from "../../src/cli/secrets.js";
import { randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  SurrogateEchoScanner, MAX_SURROGATE_ECHO_SCAN_BYTES, MAX_PLACEHOLDERS_PER_REQUEST,
  SURROGATE_UPSTREAM_CONNECT_DEADLINE_MS,
} from "../../src/credential-surrogate/index.js";
import type { SurrogateEchoEvent } from "../../src/egress-gate/gate-server.js";
import { clean, directory, binding, helper, tlsUpstream, daemon, HOST, UID } from "./surrogate-forward-fixture.js";

afterEach(async () => { vi.restoreAllMocks(); await clean(); });
const secretValue = () => randomBytes(16).toString("hex"); // 16 bytes become 32 ASCII bytes.
type ClientResult = { status: number; headers: http.IncomingHttpHeaders; body: Buffer; complete: boolean };
async function receive(port: number, authorization: string, headers: http.OutgoingHttpHeaders = {}): Promise<ClientResult> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let incoming: IncomingMessage | undefined;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ status: incoming?.statusCode ?? 0, headers: incoming?.headers ?? {}, body: Buffer.concat(chunks), complete: incoming?.complete ?? false });
    };
    const client = http.request({ hostname: "127.0.0.1", port, method: "POST", path: `http://${HOST}/`,
      headers: { Host: HOST, "Proxy-Authorization": authorization, Connection: "close", ...headers } }, response => {
      incoming = response;
      response.on("data", chunk => chunks.push(Buffer.from(chunk)));
      response.on("error", finish);
      response.on("close", finish);
      response.on("end", finish);
    });
    const timer = setTimeout(() => { client.destroy(); reject(new Error("echo fixture deadline")); }, MAX_PLACEHOLDERS_PER_REQUEST * SURROGATE_UPSTREAM_CONNECT_DEADLINE_MS);
    client.on("error", finish);
    client.end();
  });
}
async function setup(handler: (request: IncomingMessage, response: ServerResponse) => void, count = 1, onIncoming?: (incoming: IncomingMessage) => void) {
  const dir = await directory();
  const bindings = Array.from({ length: count }, (_, i) => binding(i + 1, `X-Credential-${i}`));
  const values = bindings.map(secretValue);
  const h = await helper(dir, bindings);
  for (let i = 0; i < count; i++) await h.unlock(bindings[i]!, values[i]!);
  const upstream = await tlsUpstream(dir);
  upstream.server.removeAllListeners("request");
  upstream.server.on("request", handler);
  const gate = await daemon(dir, { upstreamRequest: (options, listener) => upstream.dial(options, incoming => {
    onIncoming?.(incoming);
    listener(incoming);
  }) });
  const headers = Object.fromEntries(bindings.map(b => [b.header, b.placeholder]));
  const run = (swap = true) => receive(gate.port, gate.header, swap ? headers : {});
  const echoes = () => gate.events.filter((e): e is SurrogateEchoEvent => e.kind === "surrogate_echo_blocked" || e.kind === "surrogate_echo_unscanned");
  const assertSafeEvents = () => {
    const log = JSON.stringify([...gate.events, ...h.events]);
    expect(values.some(v => log.includes(v))).toBe(false);
    expect(bindings.some(b => log.includes(b.placeholder))).toBe(false);
    expect(log.includes('"message"')).toBe(false);
    const answered = h.events.filter(e => e.kind === "query_answered");
    for (const event of echoes()) {
      expect(event.authority).toBe(`${HOST}:443`);
      expect(answered.some(e => e.kind === "query_answered" && e.correlationId === event.correlationId)).toBe(true);
      expect("binding" in event).toBe(false);
    }
  };
  const assertCliEvents = async () => {
    const path = join(dir, "gate-events.log");
    // Only already-redacted events enter this fixture log.
    await writeFile(path, gate.events.map(e => `[egress-gate] ${JSON.stringify(e)}`).join("\n"));
    let printed = "";
    const out = new Writable({ write(chunk, _encoding, done) { printed += chunk.toString(); done(); } });
    const code = await runSecretsCommand({ argv: ["surrogate", "events", "--agent", "hermes", "--agent-uid", String(UID)],
      storagePath: dir, effectiveUid: 0, gateLogPathOverride: path, out, err: out });
    expect(code).toBe(0);
    for (const event of echoes()) expect(printed.includes(event.kind)).toBe(true);
    expect(values.some(v => printed.includes(v))).toBe(false);
    expect(bindings.some(b => printed.includes(b.placeholder))).toBe(false);
  };
  return { ...gate, upstream, values, bindings, h, run, echoes, assertSafeEvents, assertCliEvents };
}

describe("wired surrogate echo consumer", () => {
  it("header echo returns 502 with no body and joins every swapped helper query", async () => {
    const fixture = await setup((request, response) => {
      const values = String(request.headers["x-credential-1"]);
      response.setHeader("X-Reflection", ["safe", values]);
      response.setHeader("Content-Encoding", "gzip");
      response.end(randomBytes(MAX_PLACEHOLDERS_PER_REQUEST * secretValue().length));
    }, 2); // Two swaps prove helper-query attribution covers the whole request.
    const result = await fixture.run();
    expect(result.status).toBe(502);
    expect(result.headers["x-sanctuary-gate"]).toBe("surrogate-echo-blocked");
    expect(result.body.length).toBe(0);
    expect(result.headers["x-reflection"]).toBeUndefined();
    expect(fixture.echoes()).toHaveLength(2);
    expect(fixture.echoes().every(e => e.kind === "surrogate_echo_blocked" && e.code === "echo_blocked" && e.status === 502 && e.responseBytes === 0)).toBe(true);
    expect(fixture.events.some(e => e.kind === "surrogate_swap" && e.status !== 0)).toBe(false);
    fixture.assertSafeEvents();
    await fixture.assertCliEvents();
  });
  it.each([
    ["duplicate identity", ["identity", "identity"]],
    ["identity list", "identity, IDENTITY"],
    ["empty identity", ""],
  ] as const)("screens plaintext with %s coding", async (_name, encoding) => {
    const fixture = await setup((request, response) => {
      response.setHeader("Content-Encoding", [...(typeof encoding === "string" ? [encoding] : encoding)]);
      response.end(String(request.headers["x-credential-0"]));
    });
    const result = await fixture.run();
    expect(result.body.length).toBe(0);
    expect(result.complete && result.status === 200).toBe(false);
    expect(fixture.echoes()).toHaveLength(1);
    fixture.assertSafeEvents();
  });
  it.each([false, true])("screens response field names after normalization: %s", async uppercase => {
    const fixture = await setup((request, response) => {
      const value = String(request.headers["x-credential-0"]);
      response.setHeader(uppercase ? value.toUpperCase() : value, "1");
      response.end();
    });
    const result = await fixture.run();
    expect(result.status).toBe(502);
    expect(Object.keys(result.headers).some(name => name.includes(fixture.values[0]!))).toBe(false);
    expect(result.body.length).toBe(0);
    expect(fixture.echoes()).toHaveLength(1);
    expect(fixture.echoes()[0]?.kind).toBe("surrogate_echo_blocked");
    fixture.assertSafeEvents();
  });
  it("fails closed with a cause when header scanning throws", async () => {
    const fixture = await setup((request, response) => { response.end(String(request.headers["x-credential-0"])); });
    vi.spyOn(SurrogateEchoScanner.prototype, "headersEcho").mockImplementation(() => { throw new Error("scan fault"); });
    const result = await fixture.run();
    expect(result.body.length).toBe(0);
    expect(result.status).toBe(502);
    expect(fixture.echoes()).toHaveLength(1);
    const event = fixture.echoes()[0];
    expect(event?.kind === "surrogate_echo_unscanned" && event.cause).toBe("scan_error");
    fixture.assertSafeEvents();
  });
  it("screens the normalized header values that are forwarded", async () => {
    const parts = [secretValue(), secretValue()];
    const fixture = await setup((_request, response) => {
      response.setHeader("X-Reflection", parts);
      response.end();
    });
    fixture.values[0] = parts.join(", ");
    await fixture.h.unlock(fixture.bindings[0]!, fixture.values[0]!);
    const result = await fixture.run();
    expect(result.status).toBe(502);
    expect(result.body.length).toBe(0);
    expect(result.headers["x-reflection"]).toBeUndefined();
    expect(fixture.echoes()[0]?.kind).toBe("surrogate_echo_blocked");
    fixture.assertSafeEvents();
  });
  it("delivers non-echo identity lists byte for byte", async () => {
    const body = randomBytes(secretValue().length);
    const fixture = await setup((_request, response) => {
      response.setHeader("Content-Encoding", ["identity", "IDENTITY"]);
      response.end(body);
    });
    const result = await fixture.run();
    expect(result.complete).toBe(true);
    expect(result.body.equals(body)).toBe(true);
    expect(fixture.echoes()).toHaveLength(0);
  });
  it.each(["br", "identity, gzip", "identity,"])("refuses unsupported or malformed coding %s", async encoding => {
    const fixture = await setup((request, response) => {
      response.setHeader("Content-Encoding", encoding);
      response.end(String(request.headers["x-credential-0"]));
    });
    const result = await fixture.run();
    expect(result.status).toBe(502);
    expect(result.body.length).toBe(0);
    expect(fixture.echoes()).toHaveLength(1);
    const event = fixture.echoes()[0];
    expect(event?.kind === "surrogate_echo_unscanned" && event.cause).toBe("encoding");
    fixture.assertSafeEvents();
  });
  it.each(["scan", "finish"] as const)("fails closed on asynchronous %s failure and ignores late callbacks", async method => {
    let incoming: IncomingMessage | undefined;
    let scanner: SurrogateEchoScanner | undefined;
    const fixture = await setup((_request, response) => { response.end(Buffer.from("!")); }, 1, response => { incoming = response; });
    vi.spyOn(SurrogateEchoScanner.prototype, method).mockImplementation(function (this: SurrogateEchoScanner) {
      scanner = this;
      throw new Error("scan fault");
    });
    const result = await fixture.run();
    expect(result.complete && result.status === 200).toBe(false);
    expect(result.body.length).toBe(0);
    expect(scanner?.metrics.state).toBe("ABORTED");
    expect(scanner?.metrics.carryBytes).toBe(0);
    incoming!.emit("data", Buffer.from(fixture.values[0]!));
    incoming!.emit("end");
    expect(fixture.echoes()).toHaveLength(1);
    const event = fixture.echoes()[0];
    expect(event?.kind === "surrogate_echo_unscanned" && event.cause).toBe("scan_error");
    expect(fixture.events.some(e => e.kind === "surrogate_swap" && e.status !== 0)).toBe(false);
    fixture.assertSafeEvents();
  });
  it("identity body truncates with zero value bytes at every upstream split offset", async () => {
    let split = 1;
    let releaseTail: (() => void) | undefined;
    const chunkSizes: number[] = [];
    const fixture = await setup((request, response) => {
      const value = String(request.headers["x-credential-0"]);
      response.setHeader("Content-Encoding", "identity");
      response.setHeader("Content-Length", Buffer.byteLength(value));
      releaseTail = () => response.end(value.slice(split));
      response.write(value.slice(0, split));
    }, 1, incoming => {
      // Release the second TLS write only after the real incoming stream delivered its prefix.
      // This also runs with the guard removed, so the fail-before remains an assertion failure.
      incoming.once("data", (chunk: Buffer) => {
        chunkSizes.push(chunk.length);
        setImmediate(() => releaseTail!());
      });
    });
    for (; split < fixture.values[0]!.length; split++) {
      const result = await fixture.run();
      expect(result.complete).toBe(false);
      expect(result.body.length).toBe(0);
      expect(chunkSizes.at(-1)).toBe(split);
    }
    expect(fixture.echoes()).toHaveLength(split - 1);
    expect(fixture.echoes().every(e => e.kind === "surrogate_echo_blocked" && e.code === "echo_blocked")).toBe(true);
    fixture.assertSafeEvents();
  });
  it("past-ceiling echo is refused with one ceiling event", async () => {
    let expected = Buffer.alloc(0);
    const fixture = await setup((request, response) => {
      expected = Buffer.concat([Buffer.alloc(MAX_SURROGATE_ECHO_SCAN_BYTES, "!"), Buffer.from(String(request.headers["x-credential-0"]))]);
      response.end(expected);
    });
    const result = await fixture.run();
    expect(result.complete).toBe(false);
    expect(result.body.length).toBeLessThan(MAX_SURROGATE_ECHO_SCAN_BYTES);
    expect(result.body.includes(Buffer.from(fixture.values[0]!))).toBe(false);
    expect(fixture.echoes()).toHaveLength(1);
    const event = fixture.echoes()[0];
    expect(event?.kind === "surrogate_echo_unscanned" && event.cause).toBe("ceiling");
    fixture.assertSafeEvents();
  });
  it.each(["Content-Encoding", "Transfer-Encoding"])("gzip echo is refused before headers with an encoding event via %s", async header => {
    let expected = Buffer.alloc(0);
    const fixture = await setup((request, response) => {
      expected = gzipSync(String(request.headers["x-credential-0"]));
      response.setHeader(header, header === "Transfer-Encoding" ? "gzip, chunked" : "gzip");
      response.end(expected);
    });
    const result = await fixture.run();
    expect(result.status).toBe(502);
    expect(result.body.length).toBe(0);
    expect(result.headers["content-encoding"]).toBeUndefined();
    expect(fixture.echoes()).toHaveLength(1);
    const event = fixture.echoes()[0];
    expect(event?.kind === "surrogate_echo_unscanned" && event.cause).toBe("encoding");
    fixture.assertSafeEvents();
    await fixture.assertCliEvents();
  });
  it.each([
    "identity", "identity, chunked", "chunked, identity", "chunked, chunked",
    "identity, identity", "identity, chunked, identity", "identity, identity, chunked",
  ])("refuses non-exact transfer coding %s before forwarding", async transfer => {
    const fixture = await setup((_request, response) => {
      response.setHeader("Transfer-Encoding", transfer);
      response.setHeader("X-Upstream", "present");
      response.end(randomBytes(secretValue().length));
    });
    const scan = vi.spyOn(SurrogateEchoScanner.prototype, "scan");
    const result = await fixture.run();
    expect(result.status).toBe(502);
    expect(result.body.length).toBe(0);
    expect(result.headers["x-upstream"]).toBeUndefined();
    expect(scan).not.toHaveBeenCalled();
    expect(fixture.echoes()).toHaveLength(1);
    expect(fixture.echoes()[0]).toMatchObject({
      kind: "surrogate_echo_unscanned", code: "echo_unscanned", cause: "encoding", responseBytes: 0,
    });
    fixture.assertSafeEvents();
  });
  it.each([undefined, "chunked", "ChUnKeD"])("scans accepted transfer coding %s", async transfer => {
    // This acceptance fixture is ordinary content, not a candidate framing prefix.
    const body = Buffer.concat([Buffer.from("!"), randomBytes(secretValue().length)]);
    const fixture = await setup((request, _response) => {
      // Explicit framing keeps the upstream serializer from choosing a different coding for whitespace variants.
      const framing = transfer === undefined ? `Content-Length: ${body.length}` : `Transfer-Encoding: ${transfer}`;
      const payload = transfer === undefined ? body : Buffer.concat([
        Buffer.from(`${body.length.toString(16)}\r\n`), body, Buffer.from("\r\n0\r\n\r\n"),
      ]);
      request.socket.end(Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\n${framing}\r\nConnection: close\r\n\r\n`), payload]));
    });
    const scan = vi.spyOn(SurrogateEchoScanner.prototype, "scan");
    const result = await fixture.run();
    expect(result.status).toBe(200);
    expect(result.complete).toBe(true);
    expect(result.body.equals(body)).toBe(true);
    expect(scan).toHaveBeenCalled();
    expect(fixture.echoes()).toHaveLength(0);
    fixture.assertSafeEvents();
  });
  it.each(["chunked\t", " \tchunked\t "])("blocks a framing-split echo with transfer whitespace %s", async transfer => {
    const fixture = await setup((request, _response) => {
      const secret = fixture.values[0]!;
      const split = Math.floor(secret.length / 2);
      const payload = [secret.slice(0, split), secret.slice(split)]
        .map(part => `${Buffer.byteLength(part).toString(16)};test=yes\r\n${part}\r\n`).join("");
      request.socket.end(`HTTP/1.1 200 OK\r\nTransfer-Encoding: ${transfer}\r\nConnection: close\r\n\r\n${payload}0\r\n\r\n`);
    });
    const result = await fixture.run();
    expect(result.complete).toBe(false);
    expect(result.body.length).toBe(0);
    expect(fixture.echoes()).toHaveLength(1);
    expect(fixture.echoes()[0]?.kind).toBe("surrogate_echo_blocked");
    fixture.assertSafeEvents();
  });
  it("passes normal chunked streaming through both screening views", async () => {
    const body = Buffer.from("ordinary response body with several writes");
    const fixture = await setup((_request, response) => {
      response.setHeader("Transfer-Encoding", "chunked");
      response.write(body.subarray(0, Math.floor(body.length / 2)));
      setImmediate(() => response.end(body.subarray(Math.floor(body.length / 2))));
    });
    const result = await fixture.run();
    expect(result.complete).toBe(true);
    expect(result.body.equals(body)).toBe(true);
    expect(fixture.echoes()).toHaveLength(0);
  });
  it.each([" ", "\t"])("refuses size-line whitespace %j through the daemon", async whitespace => {
    const fixture = await setup((request, _response) => {
      const secret = String(request.headers["x-credential-0"]);
      const halves = 2; // Two frames exercise a value crossing a frame boundary.
      const split = Math.floor(secret.length / halves);
      const hexRadix = 16;
      const payload = [secret.slice(0, split), secret.slice(split)]
        .map(part => `${Buffer.byteLength(part).toString(hexRadix)}${whitespace};ext\r\n${part}\r\n`).join("");
      request.socket.end(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\t\r\nConnection: close\r\n\r\n${payload}0\r\n\r\n`);
    });
    const result = await fixture.run();
    expect(result.body.length).toBe(0);
    expect(result.complete).toBe(false);
    expect(fixture.echoes()).toHaveLength(1);
    expect(fixture.echoes()[0]).toMatchObject({
      kind: "surrogate_echo_unscanned", code: "echo_unscanned", cause: "encoding",
    });
    expect(fixture.events.some(e => e.kind === "surrogate_swap" && e.status !== 0)).toBe(false);
    fixture.assertSafeEvents();
  });
  it.each([" ", "+"])("refuses a first size line opened by %j through the daemon", async prefix => {
    const fixture = await setup((request, _response) => {
      const secret = String(request.headers["x-credential-0"]);
      const halves = 2; // Two frames exercise a value crossing a frame boundary.
      const split = Math.floor(secret.length / halves);
      const hexRadix = 16;
      const payload = [secret.slice(0, split), secret.slice(split)]
        .map(part => `${Buffer.byteLength(part).toString(hexRadix)}\r\n${part}\r\n`).join("");
      request.socket.end(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\t\r\nConnection: close\r\n\r\n${prefix}${payload}0\r\n\r\n`);
    });
    const result = await fixture.run();
    expect(result.body.length).toBe(0);
    expect(result.complete).toBe(false);
    expect(fixture.echoes()).toHaveLength(1);
    expect(fixture.echoes()[0]).toMatchObject({ kind: "surrogate_echo_unscanned", code: "echo_unscanned", cause: "encoding" });
    fixture.assertSafeEvents();
  });
  it.each(["invalid separator", "incomplete frame"])("refuses a stripped-view framing failure: %s", async fault => {
    const fixture = await setup((request, _response) => {
      const payload = fault === "invalid separator" ? "1\r\n!XX" : "2\r\n!";
      request.socket.end(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\t\r\nConnection: close\r\n\r\n${payload}`);
    });
    const result = await fixture.run();
    expect(result.complete).toBe(false);
    expect(result.body.length).toBe(0);
    expect(fixture.echoes()).toHaveLength(1);
    expect(fixture.echoes()[0]).toMatchObject({ kind: "surrogate_echo_unscanned", cause: "encoding" });
    fixture.assertSafeEvents();
  });
  it("non-echo response is scanned and delivered byte for byte including final carry", async () => {
    const body = randomBytes(MAX_PLACEHOLDERS_PER_REQUEST * secretValue().length + 1); // Cross a multiple of the value length.
    const fixture = await setup((_request, response) => { response.end(body); });
    const scan = vi.spyOn(SurrogateEchoScanner.prototype, "scan");
    const result = await fixture.run();
    expect(result.complete).toBe(true);
    expect(result.body.equals(body)).toBe(true);
    expect(scan).toHaveBeenCalled();
    expect(fixture.echoes()).toHaveLength(0);
    fixture.assertSafeEvents();
  });
  it.each(["identity", "gzip"])("no-swap response stays unscanned and emits no echo event for %s", async encoding => {
    const body = randomBytes(MAX_SURROGATE_ECHO_SCAN_BYTES + 1);
    const fixture = await setup((_request, response) => {
      response.setHeader("Content-Encoding", encoding);
      response.setHeader("X-Reflection", fixture.values[0]!);
      response.end(body);
    });
    const scan = vi.spyOn(SurrogateEchoScanner.prototype, "scan");
    const headers = vi.spyOn(SurrogateEchoScanner.prototype, "headersEcho");
    const result = await fixture.run(false);
    expect(result.status).toBe(200);
    expect(result.complete).toBe(true);
    expect(result.body.equals(body)).toBe(true);
    expect(scan).not.toHaveBeenCalled();
    expect(headers).not.toHaveBeenCalled();
    expect(fixture.events.some(e => e.kind.startsWith("surrogate_"))).toBe(false);
  });
  it("concurrent response waves keep independent carry and scan ceilings", async () => {
    const fixture = await setup((_request, response) => { response.end(Buffer.alloc(MAX_SURROGATE_ECHO_SCAN_BYTES + 1, "!")); });
    const seen = new Set<SurrogateEchoScanner>();
    const original = SurrogateEchoScanner.prototype.scan;
    vi.spyOn(SurrogateEchoScanner.prototype, "scan").mockImplementation(function (this: SurrogateEchoScanner, chunk) {
      seen.add(this);
      const result = original.call(this, chunk);
      expect(this.metrics.scannedBytes).toBeLessThanOrEqual(MAX_SURROGATE_ECHO_SCAN_BYTES);
      expect(this.metrics.carryBytes).toBeLessThanOrEqual(fixture.values[0]!.length - 1);
      expect(this.metrics.carryBuffers).toBe(1);
      return result;
    });
    // Four simultaneous responses fit the unchanged peer lookup cap; four waves exercise reuse.
    for (let wave = 0; wave < MAX_PLACEHOLDERS_PER_REQUEST; wave++) {
      const results = await Promise.all(Array.from({ length: MAX_PLACEHOLDERS_PER_REQUEST }, () => fixture.run()));
      expect(results.every(r => !r.complete && r.body.length < MAX_SURROGATE_ECHO_SCAN_BYTES)).toBe(true);
    }
    expect(seen.size).toBe(MAX_PLACEHOLDERS_PER_REQUEST ** 2);
    expect(fixture.echoes()).toHaveLength(seen.size);
    expect(fixture.echoes().every(e => e.kind === "surrogate_echo_unscanned" && e.cause === "ceiling")).toBe(true);
    fixture.assertSafeEvents();
  });
});


describe("echo carry fault scheduling", () => {
  it.each(["client disconnect", "upstream reset"] as const)("discards carry during a stalled body after %s", async mode => {
    let heldResponse: ServerResponse | undefined;
    const fixture = await setup((request, response) => {
      heldResponse = response;
      const value = String(request.headers["x-credential-0"]);
      response.setHeader("Content-Length", value.length);
      response.write(value.slice(0, -1));
    });
    let scanner: SurrogateEchoScanner | undefined;
    let scanned!: () => void;
    const didScan = new Promise<void>(resolve => { scanned = resolve; });
    const original = SurrogateEchoScanner.prototype.scan;
    vi.spyOn(SurrogateEchoScanner.prototype, "scan").mockImplementation(function (this: SurrogateEchoScanner, chunk) {
      scanner = this;
      const result = original.call(this, chunk);
      scanned();
      return result;
    });
    const writes: Buffer[] = [];
    const originalWrite = http.ServerResponse.prototype.write;
    vi.spyOn(http.ServerResponse.prototype, "write").mockImplementation(function (this: ServerResponse, ...args: Parameters<ServerResponse["write"]>) {
      if (this.req.url?.startsWith("http://")) writes.push(Buffer.from(args[0]));
      return Reflect.apply(originalWrite, this, args);
    });
    const client = http.request({ hostname: "127.0.0.1", port: fixture.port, method: "POST", path: `http://${HOST}/`,
      headers: { Host: HOST, "Proxy-Authorization": fixture.header, Connection: "close",
        [fixture.bindings[0]!.header]: fixture.bindings[0]!.placeholder } });
    client.on("error", () => {});
    const closed = new Promise<void>(resolve => client.once("close", resolve));
    try {
      client.end();
      await didScan;
      expect(scanner?.metrics.carryBytes).toBe(fixture.values[0]!.length - 1);
      expect(writes.length).toBe(0);
      if (mode === "client disconnect") client.destroy();
      else heldResponse!.destroy();
      await vi.waitFor(() => expect(scanner?.metrics.state).toBe("ABORTED"));
      // Release after the fault: neither a late end nor the retained prefix may reach the client.
      heldResponse!.end(fixture.values[0]!.slice(-1));
      await closed;
      expect(scanner?.metrics.carryBytes).toBe(0);
      expect(writes.length).toBe(0);
      expect(fixture.events.some(e => e.kind === "surrogate_swap" && e.status !== 0)).toBe(false);
      expect(fixture.echoes()).toHaveLength(1);
      const event = fixture.echoes()[0];
      expect(event?.kind === "surrogate_echo_unscanned" && event.cause).toBe(mode === "client disconnect" ? "client_abort" : "upstream_reset");
      fixture.assertSafeEvents();
    } finally { client.destroy(); heldResponse?.destroy(); }
  });
});
