// fail-before-exempt: new bounded loopback transport module with no base behavior.
import { createServer, type Server, type RequestListener } from "node:http";
import { connect } from "node:net";
import { readFileSync } from "node:fs";
import { once } from "node:events";
import { afterEach, expect, it } from "vitest";
import { resolveLoopbackConnectTarget } from "../../src/intelligence/loopback-endpoint.js";
import { SensitiveGenerationClient, STREAM_LINE_MAX_BYTES, STREAM_FINAL_LINE_MAX_BYTES,
  STREAM_TOTAL_MAX_BYTES, TAGS_RESPONSE_MAX_BYTES } from "../../src/intelligence/sensitive-generation-client.js";

const servers: Server[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    if (server.listening) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
async function listen(handler: RequestListener, host = "127.0.0.1") {
  const server = createServer(handler);
  servers.push(server);
  server.listen(0, host);
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("listener address");
  const resolved = resolveLoopbackConnectTarget(`http://${host}:${address.port}`);
  if (!resolved.ok) throw new Error("loopback fixture");
  return { server, target: resolved.target, client: new SensitiveGenerationClient(resolved.target) };
}
// A single token is sufficient for transport cases; the context and visible-text caps are explicit caller bounds.
const input = { model: "fixture", prompt: "fixture", numPredict: 1, numCtx: 1, visibleTextMaxBytes: STREAM_LINE_MAX_BYTES };
const progress = JSON.stringify({ response: "hello", done: false }) + "\n";
const final = JSON.stringify({ response: "", done: true, done_reason: "stop" }) + "\n";

it("generation returns text with explicit model bounds", async () => {
  let received = "";
  const f = await listen((req, res) => {
    req.on("data", (chunk) => { received += chunk.toString(); });
    req.on("end", () => res.end(progress + final));
  });
  expect(await f.client.generate(input)).toEqual({ ok: true, text: "hello", done_reason: "stop" });
  expect(JSON.parse(received)).toEqual({ model: "fixture", prompt: "fixture", stream: true, options: { num_predict: 1, num_ctx: 1 } });
});
it("tags return a bounded strict JSON payload", async () => {
  const f = await listen((_req, res) => res.end('{"models":[]}'));
  expect(await f.client.fetchTags()).toEqual({ ok: true, payload: { models: [] } });
});
it("a 307 to another listener is refused and that listener sees no connection", async () => {
  const other = await listen((_req, res) => res.end(final));
  let connections = 0;
  other.server.on("connection", () => { connections++; });
  const f = await listen((_req, res) => { res.writeHead(307, { location: `http://127.0.0.1:${other.target.port}` }); res.end(); });
  expect(await f.client.generate(input)).toEqual({ ok: false, reason: "redirect" });
  expect(connections).toBe(0);
});
it("proxy settings in the environment are ignored", async () => {
  const capture = await listen((_req, res) => res.end());
  let connections = 0;
  capture.server.on("connection", () => { connections++; });
  const f = await listen((_req, res) => res.end(progress + final));
  const saved = new Map(["HTTP_PROXY", "HTTPS_PROXY", "NODE_USE_ENV_PROXY"].map((key) => [key, process.env[key]]));
  try {
    process.env.HTTP_PROXY = process.env.HTTPS_PROXY = `http://127.0.0.1:${capture.target.port}`;
    process.env.NODE_USE_ENV_PROXY = "1";
    expect(await f.client.generate(input)).toEqual({ ok: true, text: "hello", done_reason: "stop" });
    expect(connections).toBe(0);
  } finally {
    for (const [key, value] of saved) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
});
it("the client never calls fetch", () => {
  const source = readFileSync(new URL("../../src/intelligence/sensitive-generation-client.ts", import.meta.url), "utf8");
  expect(source).not.toMatch(/\bfetch\s*\(/);
});
it("a connection whose remote address differs is closed before any body byte", async () => {
  let bytes = 0;
  const other = await listen((req, res) => { req.on("data", (chunk) => { bytes += chunk.length; }); req.on("end", () => res.end(final)); }, "127.0.0.2");
  const f = await listen((_req, res) => res.end(final));
  const client = new SensitiveGenerationClient(f.target, { connect: () => connect({ host: other.target.address, port: other.target.port }) });
  expect(await client.generate(input)).toEqual({ ok: false, reason: "connect_address_mismatch" });
  expect(bytes).toBe(0);
});
it.each([
  ["line_cap", "!".repeat(STREAM_LINE_MAX_BYTES + 1) + "\n" + final],
  ["final_line_cap", "!".repeat(STREAM_FINAL_LINE_MAX_BYTES + 1) + "\n"],
  ["total_cap", (JSON.stringify({ response: "", done: false }) + "\n").repeat(Math.ceil(STREAM_TOTAL_MAX_BYTES / Buffer.byteLength(JSON.stringify({ response: "", done: false }) + "\n")) + 1) + final],
  ["visible_text_cap", '{"response":"hello","done":false} invalid\n' + final],
])("%s refuses before parsing an over-budget frame", async (reason, body) => {
  const f = await listen((_req, res) => res.end(body));
  expect(await f.client.generate({ ...input, visibleTextMaxBytes: 1 })).toEqual({ ok: false, reason });
});
it("an over-cap tags payload is refused", async () => {
  const f = await listen((_req, res) => res.end(" ".repeat(TAGS_RESPONSE_MAX_BYTES + 1)));
  expect(await f.client.fetchTags()).toEqual({ ok: false, reason: "tags_cap" });
});
it("a call without num_predict is refused before any connection", async () => {
  const f = await listen((_req, res) => res.end(final));
  let connections = 0;
  f.server.on("connection", () => { connections++; });
  expect(await f.client.generate({ ...input, numPredict: undefined as unknown as number })).toEqual({ ok: false, reason: "num_predict_missing" });
  expect(connections).toBe(0);
});
it("a stalled stream times out and a reply that arrives after the timeout is discarded", async () => {
  let timeout: (() => void) | undefined;
  let release: (() => void) | undefined;
  let started!: () => void;
  const incoming = new Promise<void>((resolve) => { started = resolve; });
  const f = await listen((_req, res) => { release = () => res.end(progress + final); started(); });
  const client = new SensitiveGenerationClient(f.target, { setTimer: (callback) => { timeout = callback; }, clearTimer: () => undefined });
  const result = client.generate(input);
  await incoming;
  timeout!();
  expect(await result).toEqual({ ok: false, reason: "timeout" });
  release!();
  expect(await result).toEqual({ ok: false, reason: "timeout" });
});
it("non-success statuses return no response bytes", async () => {
  const f = await listen((_req, res) => { res.writeHead(503); res.end("private response"); }); // HTTP service unavailable.
  expect(await f.client.generate(input)).toEqual({ ok: false, reason: "http_status" });
});
it.each([
  '{"response":"first","response":"second","done":true,"done_reason":"stop"}\n',
  '{"response":"unfinished","done":false}\n',
  'not json\n',
])("invalid frames return no response bytes: %s", async (body) => {
  const f = await listen((_req, res) => res.end(body));
  expect(await f.client.generate(input)).toEqual({ ok: false, reason: "invalid_response" });
});
it("a large final context line remains within its separate allowance", async () => {
  const body = JSON.stringify({ response: "hello", done: true, done_reason: "length", context: Array(STREAM_LINE_MAX_BYTES).fill(1) }) + "\n";
  expect(Buffer.byteLength(body)).toBeGreaterThan(STREAM_LINE_MAX_BYTES);
  expect(Buffer.byteLength(body)).toBeLessThan(STREAM_FINAL_LINE_MAX_BYTES);
  const f = await listen((_req, res) => res.end(body));
  expect(await f.client.generate(input)).toEqual({ ok: true, text: "hello", done_reason: "length" });
});
it("cancellation closes a pending request", async () => {
  let started!: () => void;
  const incoming = new Promise<void>((resolve) => { started = resolve; });
  const f = await listen(() => started());
  const controller = new AbortController();
  const result = f.client.generate({ ...input, signal: controller.signal });
  await incoming;
  controller.abort();
  expect(await result).toEqual({ ok: false, reason: "cancelled" });
});
it("a connect failure has a closed refusal reason", async () => {
  const f = await listen((_req, res) => res.end(final));
  const client = new SensitiveGenerationClient(f.target, { connect: () => { throw new Error("private transport details"); } });
  expect(await client.generate(input)).toEqual({ ok: false, reason: "transport" });
});
it("a different connected port is refused before body bytes", async () => {
  let bytes = 0;
  const other = await listen((req, res) => {
    req.on("data", (chunk) => { bytes += chunk.length; });
    req.on("end", () => res.end(final));
  });
  const expected = await listen((_req, res) => res.end(final));
  const client = new SensitiveGenerationClient(expected.target, {
    connect: () => connect({ host: other.target.address, port: other.target.port }),
  });
  expect(await client.generate(input)).toEqual({ ok: false, reason: "connect_address_mismatch" });
  expect(bytes).toBe(0);
});
it("an untrusted non-loopback target opens no socket", async () => {
  let opened = false;
  const client = new SensitiveGenerationClient({ address: "10.0.0.1", port: 80, family: 4 }, { // HTTP default port.
    connect: () => { opened = true; throw new Error("unexpected connection"); },
  });
  expect(await client.generate(input)).toEqual({ ok: false, reason: "not_loopback" });
  expect(opened).toBe(false);
});
it("a still-open stream is closed when its unfinished line exceeds the cap", async () => {
  const f = await listen((_req, res) => { res.write("!".repeat(STREAM_FINAL_LINE_MAX_BYTES + 1)); });
  expect(await f.client.generate(input)).toEqual({ ok: false, reason: "final_line_cap" });
});
