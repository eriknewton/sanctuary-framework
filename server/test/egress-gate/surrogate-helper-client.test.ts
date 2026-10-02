/** Capability: one-shot queries fail closed under late, fragmented and foreign replies. */
import net from "node:net";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  SURROGATE_QUERY_TIMEOUT_MS, SURROGATE_WIRE_MAX_FRAME_BYTES,
  encodeSurrogateQueryResponse, parseSurrogateQueryRequest, newSurrogateCorrelationId,
  mintSurrogatePlaceholder, type SurrogateQueryRequest,
} from "../../src/credential-surrogate/index.js";
import { createSurrogateHelperClient } from "../../src/egress-gate/surrogate-helper-client.js";
import { surrogateQuerySocketPath } from "../../src/egress-gate/surrogate-helper-daemon.js";
import type { SurrogateUpstreamRequest } from "../../src/egress-gate/gate-server.js";
import { clean, cleanup, directory, daemon, raw, request, helper, binding, HOST, UID } from "./surrogate-forward-fixture.js";

afterEach(clean);
async function fakeHelper(dir: string, act: (s: net.Socket, q: SurrogateQueryRequest) => void) {
  const queries: SurrogateQueryRequest[] = []; const sockets = new Set<net.Socket>();
  const server = net.createServer(s => {
    sockets.add(s); s.on("close", () => sockets.delete(s)); s.on("error", () => {});
    s.once("data", chunk => {
      const q = parseSurrogateQueryRequest(chunk.toString().trim());
      if (!q) { s.destroy(); return; } queries.push(q); act(s, q);
    });
  });
  await new Promise<void>(r => server.listen(surrogateQuerySocketPath(UID, dir), r));
  cleanup.push(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => server.close(() => r())); });
  return { queries };
}
const input = () => ({ placeholder: mintSurrogatePlaceholder(), host: HOST, port: 443, location: "header:authorization" });

describe("one-shot helper fault schedule", () => {
  it.each(["silent", "late", "mid_reply", "wrong_id", "second_frame", "split_second_frame", "oversize", "rate_limited"])("%s never resolves or dials an upstream", async mode => {
    const dir = await directory();
    const timers: ReturnType<typeof setTimeout>[] = []; cleanup.push(async () => { timers.forEach(clearTimeout); });
    const fake = await fakeHelper(dir, (s, q) => {
      const frame = encodeSurrogateQueryResponse({ v: 1, id: mode === "wrong_id" ? newSurrogateCorrelationId() : q.id, kind: "swap", value: randomBytes(20).toString("hex") });
      switch (mode) {
        case "silent": break;
        case "late": timers.push(setTimeout(() => s.end(frame), SURROGATE_QUERY_TIMEOUT_MS + 50)); break;
        case "mid_reply": s.end(frame.subarray(0, frame.length / 2)); break;
        case "second_frame": s.end(Buffer.concat([frame, frame])); break;
        case "split_second_frame": s.write(frame); timers.push(setTimeout(() => s.end(frame), 20)); break;
        case "oversize": s.write(Buffer.alloc(SURROGATE_WIRE_MAX_FRAME_BYTES + 1, 32)); break;
        case "rate_limited": s.end(encodeSurrogateQueryResponse({ v: 1, id: q.id, kind: "deny", reason: "rate_limited" })); break;
        default: s.end(frame);
      }
    });
    const dial = vi.fn<SurrogateUpstreamRequest>(); const gate = await daemon(dir, { upstreamRequest: dial });
    const result = await raw(gate.port, request(gate.header, `Authorization: ${mintSurrogatePlaceholder()}\r\n`));
    expect(result.includes("503 Service Unavailable")).toBe(true);
    await new Promise(r => setTimeout(r, 75));
    expect(gate.resolver.resolve).not.toHaveBeenCalled(); expect(dial).not.toHaveBeenCalled();
    expect(gate.events.filter(e => e.kind.startsWith("surrogate_")).length).toBe(1);
    expect(gate.events.filter(e => e.kind.startsWith("surrogate_")).every(e => "correlationId" in e && e.correlationId === fake.queries[0]?.id)).toBe(true);
    if (mode !== "rate_limited") {
      const expected = mode === "silent" || mode === "late" ? "helper_timeout" : mode === "wrong_id" ? "helper_id_mismatch" : "helper_malformed";
      expect(gate.events.some(e => e.kind === "surrogate_helper_unavailable" && e.code === expected)).toBe(true);
    }
  });
  it("repeated two-request timeout then release waves never cross values or settle twice", async () => {
    const dir = await directory(); const pending: { socket: net.Socket; query: SurrogateQueryRequest }[] = [];
    const fake = await fakeHelper(dir, (socket, query) => pending.push({ socket, query }));
    const dial = vi.fn<SurrogateUpstreamRequest>(); const gate = await daemon(dir, { upstreamRequest: dial });
    const a = mintSurrogatePlaceholder(); const b = mintSurrogatePlaceholder();
    const values = [randomBytes(20).toString("hex"), randomBytes(20).toString("hex")];
    for (let wave = 0; wave < 3; wave++) {
      const responses = await Promise.all([a, b].map(p => raw(gate.port, request(gate.header, `Authorization: ${p}\r\n`))));
      expect(responses.every(s => s.includes("503 Service Unavailable"))).toBe(true);
      for (const { socket, query } of pending.splice(0)) socket.end(encodeSurrogateQueryResponse({ v: 1, id: query.id, kind: "swap", value: values[query.placeholder === a ? 0 : 1]! }));
      await new Promise(r => setTimeout(r, 20));
      expect(dial).not.toHaveBeenCalled(); expect(gate.resolver.resolve).not.toHaveBeenCalled();
    }
    expect(fake.queries).toHaveLength(6); expect(new Set(fake.queries.map(q => q.id)).size).toBe(6);
    expect(gate.events.filter(e => e.kind === "surrogate_helper_unavailable")).toHaveLength(6);
    expect(values.some(v => JSON.stringify(gate.events).includes(v))).toBe(false);
  }, 12_000);
  it("successful concurrent queries use fresh connections and ids with no cross-value reply", async () => {
    const dir = await directory(); const a = input(); const b = input();
    const first = randomBytes(20).toString("hex"); const second = randomBytes(20).toString("hex");
    const fake = await fakeHelper(dir, (s, q) => s.end(encodeSurrogateQueryResponse({ v: 1, id: q.id, kind: "swap", value: q.placeholder === a.placeholder ? first : second })));
    const client = createSurrogateHelperClient(UID, dir); const results = await Promise.all([client.query(a), client.query(b)]);
    expect(results.every((r, i) => r.kind === "response" && r.response.kind === "swap" && r.response.value === [first, second][i])).toBe(true);
    expect(fake.queries).toHaveLength(2); expect(new Set(fake.queries.map(q => q.id)).size).toBe(2);
  });
});


it("helper denials carry only an id recovered from a parsed frame", async () => {
  const dir = await directory(); const h = await helper(dir, [binding()]);
  const id = newSurrogateCorrelationId();
  for (const frame of [JSON.stringify({ v: 2, id }), "invalid-json"]) {
    await new Promise<void>((resolve, reject) => {
      const s = net.connect(h.querySocketPath, () => s.write(`${frame}\n`));
      s.resume(); s.on("end", resolve); s.on("error", reject);
    });
  }
  const denials = h.events.filter(e => e.kind === "query_denied");
  expect(denials).toHaveLength(2);
  expect(denials[0]?.kind === "query_denied" && denials[0].correlationId === id).toBe(true);
  expect(denials[1]?.kind === "query_denied" && denials[1].correlationId === undefined).toBe(true);
});


it("client disconnect after send retains the unanswered query id", async () => {
  const dir = await directory();
  const fake = await fakeHelper(dir, () => {});
  const dial = vi.fn<SurrogateUpstreamRequest>(); const gate = await daemon(dir, { upstreamRequest: dial });
  const socket = net.connect(gate.port, "127.0.0.1", () => socket.write(request(gate.header, `Authorization: ${mintSurrogatePlaceholder()}\r\n`)));
  socket.on("error", () => {}); cleanup.push(async () => { socket.destroy(); });
  await vi.waitFor(() => expect(fake.queries).toHaveLength(1));
  socket.destroy();
  await vi.waitFor(() => expect(gate.events.some(e => e.kind === "surrogate_denied" && e.correlationId === fake.queries[0]!.id)).toBe(true));
  expect(gate.resolver.resolve).not.toHaveBeenCalled(); expect(dial).not.toHaveBeenCalled();
});
