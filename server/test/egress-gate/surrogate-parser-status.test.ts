/** Capability: bounded request provenance and consistent framing refusals across socket schedules. */
import net from "node:net";
import { randomBytes } from "node:crypto";
import http from "node:http";
import { afterEach, expect, it, vi } from "vitest";
import { clean, directory, daemon, direct, listen, raw, tlsUpstream, request, HOST, UID } from "./surrogate-forward-fixture.js";

afterEach(clean);
// Separate writes by one scheduling window; the deadline bounds every fixture socket and timer.
const FRAGMENT_DELAY_MS = 100;
const EXCHANGE_DEADLINE_MS = 10_000;
async function exchange(port: number, first: string, second: string, finish = false): Promise<string> {
  return new Promise((resolve, reject) => {
    let fragment: ReturnType<typeof setTimeout> | undefined;
    const socket = net.connect(port, "127.0.0.1", () => {
      socket.write(first);
      fragment = setTimeout(() => { if (finish) socket.end(second); else socket.write(second); }, FRAGMENT_DELAY_MS);
    });
    let output = "";
    const timer = setTimeout(() => socket.destroy(new Error("fixture deadline")), EXCHANGE_DEADLINE_MS);
    socket.on("data", chunk => { output += chunk.toString(); });
    socket.on("error", reject);
    socket.on("close", () => { clearTimeout(timer); clearTimeout(fragment); resolve(output); });
  });
}

it("fragmented duplicate length preserves the dispatch reason", async () => {
  const query = vi.fn();
  const gate = await direct({ forwardMode: { destinations: [], helperClient: { query } } });
  const wire = request(gate.header, "Content-Length: 0\r\n");
  const fragmented = await exchange(gate.port, wire.slice(0, -2), "Content-Length: 0\r\n\r\n");
  const whole = await exchange(gate.port, wire.slice(0, -2) + "Content-Length: 0\r\n\r\n", "");
  expect(fragmented).toBe(whole);
  expect(fragmented).toContain("400 Bad Request");
  expect(fragmented).toContain("surrogate-duplicate-header");
  expect(query).not.toHaveBeenCalled(); expect(gate.resolver.resolve).not.toHaveBeenCalled();
});

it("raw short body preserves the dispatch 502", async () => {
  const dir = await directory(); const upstream = await tlsUpstream(dir);
  const gate = await daemon(dir, { upstreamRequest: upstream.dial });
  const result = await exchange(gate.port, request(gate.header, "Content-Length: 2\r\n") + randomBytes(1).toString("hex").slice(0, 1), "", true);
  expect(result).toContain("502 Bad Gateway");
  expect(result).toContain("body_length_mismatch");
  expect(upstream.received).toHaveLength(0);
  expect(gate.events.filter(event => event.kind === "surrogate_denied" && event.code === "body_length_mismatch")).toHaveLength(1);
});

it.each(["keep-alive", "pipeline"])("%s resets provenance before malformed CONNECT", async mode => {
  const gate = await daemon(await directory());
  const first = request(gate.header, "Content-Length: 0\r\n").replaceAll(HOST, "unbound.example.test").replace("Connection: close", "Connection: keep-alive");
  const next = `CONNECT ${HOST}:443 HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n`;
  const result = await exchange(gate.port, mode === "pipeline" ? first + next : first, mode === "pipeline" ? "" : next);
  expect(result).toContain("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  expect(result).not.toContain("surrogate-duplicate-header");
});

it.each(["keep-alive", "pipeline"])("%s carries only the next forward request's provenance", async mode => {
  const gate = await daemon(await directory());
  const first = request(gate.header, "Content-Length: 0\r\n").replaceAll(HOST, "unbound.example.test").replace("Connection: close", "Connection: keep-alive");
  const next = request(gate.header, "Content-Length: 0\r\n").slice(0, -2);
  const result = await exchange(gate.port, mode === "pipeline" ? first + next : first, mode === "pipeline" ? "Content-Length: 0\r\n\r\n" : next + "Content-Length: 0\r\n\r\n");
  expect(result).toContain("surrogate-duplicate-header");
});

it("short body while authentication waits cannot resume a late dial", async () => {
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const query = vi.fn(); const dial = vi.fn(); const authorize = vi.fn();
  const gate = await direct({
    livenessProbe: { coalescing: "forbidden", binding: { agentUid: UID, gatePort: 19998 }, check: async () => { await pending; return { live: true, reasons: [] }; } },
    clientAuth: { agentUid: UID, authorize }, upstreamRequest: dial,
    forwardMode: { destinations: [`${HOST}:443`], helperClient: { query } },
  });
  try {
    const result = await exchange(gate.port, request(gate.header, "Content-Length: 2\r\n") + "a", "", true);
    expect(result).toContain("502 Bad Gateway");
  } finally { release(); }
  await new Promise<void>(resolve => setImmediate(resolve));
  expect(authorize).not.toHaveBeenCalled(); expect(query).not.toHaveBeenCalled(); expect(dial).not.toHaveBeenCalled();
  expect(gate.resolver.resolve).not.toHaveBeenCalled();
});

it("oversized fragmented headers exhaust one header budget without helper admission", async () => {
  const query = vi.fn(); const gate = await direct({ forwardMode: { destinations: [], helperClient: { query } } });
  const result = await exchange(gate.port, `GET http://${HOST}/ HTTP/1.1\r\nX-Fill: `, "a".repeat(http.maxHeaderSize) + "\r\n\r\n");
  expect(result).toContain("431 Request Header Fields Too Large");
  expect(query).not.toHaveBeenCalled(); expect(gate.resolver.resolve).not.toHaveBeenCalled();
});

it("separator-heavy headers preserve native overflow or the next request's provenance", async () => {
  const gate = await daemon(await directory());
  // 1800 short unique names fit older llhttp field-byte budgets but exceed the raw-byte limit.
  const fields = Array.from({ length: 1800 }, (_, i) => `X-${i}: \r\n`).join("");
  const first = request(gate.header, fields).replaceAll(HOST, "unbound.example.test").replace("Connection: close", "Connection: keep-alive");
  expect(first.length).toBeGreaterThan(http.maxHeaderSize);
  // Node releases differ in separator accounting; the native parser defines admission.
  const reference = http.createServer((_request, response) => {
    response.writeHead(405, { Connection: "close" });
    response.end();
  });
  const native = await raw(await listen(reference), first);
  const next = request(gate.header, "Content-Length: 0\r\nContent-Length: 0\r\n");
  const result = await exchange(gate.port, first, next);
  if (native.startsWith("HTTP/1.1 431")) {
    expect(result).toBe(native);
  } else {
    expect(native).toContain("405 Method Not Allowed");
    expect(result).toContain("405 Method Not Allowed");
    expect(result).toContain("surrogate-duplicate-header");
  }
  expect(gate.resolver.resolve).not.toHaveBeenCalled();
});
