/**
 * A fake local model runtime in its own process, so its work never runs on the
 * server's or the worker's event loop. It serves /api/tags and a streaming
 * /api/generate on a random loopback port, reports every request it receives
 * to its parent over IPC, and follows a scripted mode the parent can change.
 * A `count` message is answered with the number of stream frames written so far.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export type FakeMode = "normal" | "slow" | "stall" | "redirect" | "bad_digest" | "missing" | "oversized" | "non200" | "late_final";

interface Script {
  mode: FakeMode;
  tag: string;
  digest: string;
  /** Text each generate call answers with, before the call number is appended. */
  reply: string;
  /** Delay between stream lines in slow mode, and before the final line in late_final mode. */
  delay_ms: number;
}

let script: Script = { mode: "normal", tag: "qwen2.5:1.5b", digest: "1".repeat(64), reply: "summary", delay_ms: 0 };
let generateCalls = 0;
// Stream frames written across every generate call, final frames included.
let framesWritten = 0;
const open = new Set<ServerResponse>();

function line(response: ServerResponse, frame: Record<string, unknown>): void {
  response.write(`${JSON.stringify(frame)}\n`);
  framesWritten += 1;
}
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function generate(response: ServerResponse): Promise<void> {
  generateCalls += 1;
  if (script.mode === "redirect") {
    response.writeHead(302, { location: "http://127.0.0.1:1/api/generate" });
    response.end();
    return;
  }
  if (script.mode === "non200") {
    response.writeHead(500, { "content-type": "application/json" });
    response.end('{"error":"fake failure"}');
    return;
  }
  response.writeHead(200, { "content-type": "application/x-ndjson" });
  // A three-byte character, so the 2 KiB cap falls inside a sequence and the cut must back off.
  const text = script.mode === "oversized" ? "\u20ac".repeat(6_000) : `${script.reply} ${generateCalls}`;
  const words = text.match(/[\s\S]{1,64}/gu) ?? [""];
  for (const word of words) {
    line(response, { model: script.tag, response: word, done: false });
    if (script.mode === "slow") await sleep(script.delay_ms);
    if (script.mode === "stall") return; // Never finishes; the client's timeout must end it.
  }
  if (script.mode === "late_final") await sleep(script.delay_ms);
  if (response.destroyed) return;
  line(response, { model: script.tag, response: "", done: true, done_reason: "stop" });
  response.end();
}

const server = createServer((request: IncomingMessage, response: ServerResponse) => {
  open.add(response);
  response.on("close", () => open.delete(response));
  const chunks: Buffer[] = [];
  request.on("data", (chunk: Buffer) => chunks.push(chunk));
  request.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf8");
    process.send?.({
      type: "request",
      method: request.method,
      path: request.url,
      body,
      local_address: request.socket.localAddress,
      host: request.headers.host,
    });
    if (request.url === "/api/tags") {
      response.writeHead(200, { "content-type": "application/json" });
      const models = script.mode === "missing" ? [] : [{ name: script.tag, digest: script.mode === "bad_digest" ? "2".repeat(64) : script.digest }];
      response.end(JSON.stringify({ models }));
      return;
    }
    if (request.url === "/api/generate" && request.method === "POST") {
      generate(response).catch(() => response.destroy());
      return;
    }
    response.writeHead(404);
    response.end();
  });
});

process.on("message", (message: { type: string; script?: Partial<Script> }) => {
  if (message.type === "script") script = { ...script, ...message.script };
  if (message.type === "count") process.send?.({ type: "count", frames: framesWritten });
  if (message.type === "stop") {
    for (const response of open) response.destroy();
    server.close(() => process.exit(0));
  }
});
process.on("disconnect", () => process.exit(0));

server.listen(0, "127.0.0.1", () => {
  process.send?.({ type: "listening", port: (server.address() as AddressInfo).port });
});
