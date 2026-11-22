import { request, type ClientRequest, type IncomingMessage } from "node:http";
import { connect, type Socket } from "node:net";
import { TextDecoder } from "node:util";
import { parseStrictJson } from "../substrate/strict-json.js";
import { OLLAMA_RUNTIME_EVIDENCE_MAX_RESPONSE_BYTES } from "./runtime-light-verifier.js";
import { resolveLoopbackConnectTarget, type LoopbackConnectTarget } from "./loopback-endpoint.js";

const HTTP_OK = 200; // HTTP successful representation status.
const HTTP_REDIRECT_MIN = 300; // HTTP redirection status class.
const HTTP_REDIRECT_END = 400; // The next HTTP status class starts here.
const KIB = 1024; // One kibibyte is 2^10 bytes.
// A progress line holds one token and its fixed envelope.
export const STREAM_LINE_MAX_BYTES = 16 * KIB;
// 20,480 context tokens * 7 bytes plus 8 KiB visible text and the envelope fit in 192 KiB.
export const STREAM_FINAL_LINE_MAX_BYTES = 192 * KIB;
// The final-line allowance plus 64 KiB of progress lines.
export const STREAM_TOTAL_MAX_BYTES = 256 * KIB;
// Must match GENERATION_TIMEOUT_MS in intelligence/substrates/local.ts.
export const LOCAL_CALL_TIMEOUT_MS = 120_000;
// The runtime verifier and this transport use one tags byte cap.
export const TAGS_RESPONSE_MAX_BYTES = OLLAMA_RUNTIME_EVIDENCE_MAX_RESPONSE_BYTES;
export type SensitiveGenerationRefusal = "not_loopback" | "num_predict_missing" | "connect_address_mismatch" |
  "redirect" | "http_status" | "line_cap" | "final_line_cap" | "total_cap" | "visible_text_cap" |
  "tags_cap" | "timeout" | "cancelled" | "transport" | "invalid_response";
type Refusal = { ok: false; reason: SensitiveGenerationRefusal };
export type SensitiveGenerationResult = { ok: true; text: string; done_reason: string } | Refusal;
export type SensitiveTagsResult = { ok: true; payload: unknown } | Refusal;
export interface SensitiveGenerateRequest {
  model: string;
  prompt: string;
  numPredict: number;
  numCtx: number;
  visibleTextMaxBytes: number;
  signal?: AbortSignal;
}
export interface SensitiveGenerationDependencies {
  connect?: (target: LoopbackConnectTarget) => Socket;
  setTimer?: (callback: () => void, milliseconds: number) => unknown;
  clearTimer?: (timer: unknown) => void;
  timeoutMs?: number;
}
class Refused extends Error {
  constructor(readonly reason: SensitiveGenerationRefusal) { super(reason); }
}
function fail(reason: SensitiveGenerationRefusal): never { throw new Refused(reason); }
const decoder = new TextDecoder("utf-8", { fatal: true });

// A bounded lexical preflight measures the response string before the strict envelope parser runs.
// It grants no schema authority: parseStrictJson still validates the entire frame afterward.
function responseBytesBeforeParse(line: string): number {
  let depth = 0;
  let responseBytes = 0;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === "{" || char === "[") { depth++; continue; }
    if (char === "}" || char === "]") { depth--; continue; }
    if (char !== '"') continue;
    const start = i;
    let escaped = false;
    for (i++; i < line.length; i++) {
      if (!escaped && line[i] === '"') break;
      if (!escaped && line[i] === "\\") escaped = true; else escaped = false;
    }
    if (i >= line.length) fail("invalid_response");
    if (depth !== 1) continue;
    const token = JSON.parse(line.slice(start, i + 1)) as string;
    let next = i + 1;
    while (/\s/.test(line[next] ?? "") && next < line.length) next++;
    if (line[next] !== ":" || token !== "response") continue;
    next++;
    while (/\s/.test(line[next] ?? "") && next < line.length) next++;
    if (line[next] !== '"') fail("invalid_response");
    const valueStart = next;
    escaped = false;
    for (next++; next < line.length; next++) {
      if (!escaped && line[next] === '"') break;
      if (!escaped && line[next] === "\\") escaped = true; else escaped = false;
    }
    if (next >= line.length) fail("invalid_response");
    // String-token decoding handles JSON escapes; no envelope or context array is parsed here.
    responseBytes += Buffer.byteLength(JSON.parse(line.slice(valueStart, next + 1)) as string);
    i = next;
  }
  return responseBytes;
}

/** Explicit loopback transport for bounded operator-supplied model requests. */
export class SensitiveGenerationClient {
  private readonly target: LoopbackConnectTarget;
  private readonly dependencies: SensitiveGenerationDependencies;
  constructor(target: LoopbackConnectTarget, dependencies: SensitiveGenerationDependencies = {}) {
    this.target = Object.freeze({ ...target });
    this.dependencies = dependencies;
  }

  async generate(input: SensitiveGenerateRequest): Promise<SensitiveGenerationResult> {
    // A caller must bound generation before the connection can carry any prompt bytes.
    if (!Number.isSafeInteger(input.numPredict) || input.numPredict <= 0) return { ok: false, reason: "num_predict_missing" };
    if (!Number.isSafeInteger(input.numCtx) || input.numCtx <= 0 ||
      !Number.isSafeInteger(input.visibleTextMaxBytes) || input.visibleTextMaxBytes <= 0 ||
      typeof input.model !== "string" || typeof input.prompt !== "string") return { ok: false, reason: "invalid_response" };
    const body = JSON.stringify({ model: input.model, prompt: input.prompt, stream: true,
      options: { num_predict: input.numPredict, num_ctx: input.numCtx } });
    return this.perform("/api/generate", body, input.signal, async (response) => {
      // The unfinished line is kept as its received pieces and joined once, when its newline arrives
      // or the stream ends, so buffering costs work linear in the bytes received.
      const pending: Buffer[] = [];
      let pendingLength = 0;
      let total = 0;
      let visible = 0;
      let text = "";
      let finalReason: string | undefined;
      let previous: Buffer | undefined;
      const consume = (line: Buffer, final: boolean) => {
        // The last line alone receives the context-array allowance; earlier lines remain token-sized.
        if (line.length > (final ? STREAM_FINAL_LINE_MAX_BYTES : STREAM_LINE_MAX_BYTES)) fail(final ? "final_line_cap" : "line_cap");
        const decoded = decoder.decode(line);
        const measured = responseBytesBeforeParse(decoded);
        // Refuse the visible-text budget before parsing the envelope or retaining its text.
        if (visible + measured > input.visibleTextMaxBytes) fail("visible_text_cap");
        const value = parseStrictJson(decoded);
        if (!value || typeof value !== "object" || Array.isArray(value)) fail("invalid_response");
        const frame = value as Record<string, unknown>;
        if (typeof frame.response !== "string" || typeof frame.done !== "boolean" || frame.done !== final) fail("invalid_response");
        visible += Buffer.byteLength(frame.response);
        // Accumulated visible text is bounded before it enters the returned string.
        if (visible > input.visibleTextMaxBytes) fail("visible_text_cap");
        text += frame.response;
        if (final) {
          if (typeof frame.done_reason !== "string") fail("invalid_response");
          finalReason = frame.done_reason;
        }
      };
      for await (const chunk of response) {
        const bytes = Buffer.from(chunk);
        total += bytes.length;
        // Bound the entire response before buffering or parsing any new frame.
        if (total > STREAM_TOTAL_MAX_BYTES) fail("total_cap");
        let start = 0;
        let newline: number;
        while ((newline = bytes.indexOf(10, start)) !== -1) { // LF is byte 10 in NDJSON.
          pending.push(bytes.subarray(start, newline));
          const line = Buffer.concat(pending, pendingLength + newline - start);
          pending.length = 0;
          pendingLength = 0;
          start = newline + 1;
          if (previous) consume(previous, false);
          previous = line;
          if (line.length > STREAM_FINAL_LINE_MAX_BYTES) fail("final_line_cap");
        }
        if (start < bytes.length) {
          pending.push(bytes.subarray(start));
          pendingLength += bytes.length - start;
        }
        // An unfinished line is bounded before more bytes can be buffered or parsed.
        if (pendingLength > STREAM_FINAL_LINE_MAX_BYTES) fail("final_line_cap");
        if (pendingLength && previous) { consume(previous, false); previous = undefined; }
      }
      if (pendingLength) previous = Buffer.concat(pending, pendingLength);
      if (!previous) fail("invalid_response");
      consume(previous, true);
      return { ok: true, text, done_reason: finalReason! } as const;
    });
  }

  async fetchTags(): Promise<SensitiveTagsResult> {
    return this.perform("/api/tags", undefined, undefined, async (response) => {
      let total = 0;
      const chunks: Buffer[] = [];
      for await (const chunk of response) {
        const bytes = Buffer.from(chunk);
        total += bytes.length;
        // Tags share the verifier's byte cap before JSON parsing.
        if (total > TAGS_RESPONSE_MAX_BYTES) fail("tags_cap");
        chunks.push(bytes);
      }
      return { ok: true, payload: parseStrictJson(decoder.decode(Buffer.concat(chunks))) } as const;
    });
  }

  private async perform<T>(path: string, body: string | undefined, signal: AbortSignal | undefined,
    read: (response: IncomingMessage) => Promise<T>): Promise<T | Refusal> {
    const host = this.target.family === 6 ? `[${this.target.address}]` : this.target.address;
    const resolved = resolveLoopbackConnectTarget(`http://${host}:${this.target.port}/`);
    // The re-resolved target must equal the stored one in every field the connection uses.
    if (!resolved.ok || resolved.target.address !== this.target.address || resolved.target.family !== this.target.family ||
      resolved.target.port !== this.target.port)
      return { ok: false, reason: "not_loopback" };
    if (signal?.aborted) return { ok: false, reason: "cancelled" };
    return new Promise((resolve) => {
      let settled = false;
      let timer: unknown;
      let response: IncomingMessage | undefined;
      let req: ClientRequest | undefined;
      const clearTimer = this.dependencies.clearTimer ?? ((handle: unknown) => clearTimeout(handle as ReturnType<typeof setTimeout>));
      const finish = (result: T | Refusal) => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimer(timer);
        signal?.removeEventListener("abort", cancel);
        response?.destroy();
        req?.destroy();
        resolve(result);
      };
      const refuse = (reason: SensitiveGenerationRefusal) => finish({ ok: false, reason });
      const cancel = () => refuse("cancelled");
      // A custom connection with no agent bypasses global agents, proxy selection and DNS.
      try {
      req = request({ hostname: this.target.address, port: this.target.port, path,
        method: body === undefined ? "GET" : "POST", agent: undefined,
        createConnection: () => (this.dependencies.connect ?? ((target) => connect({ host: target.address, port: target.port, family: target.family })))(this.target),
        headers: { "content-type": "application/json", "connection": "close", ...(body === undefined ? {} : { "content-length": Buffer.byteLength(body) }) },
      });
      } catch { refuse("transport"); return; }
      req.on("error", () => refuse("transport"));
      req.on("socket", (socket) => {
        const checked = () => {
          if (settled) return;
          // Verify the connected peer before any prompt body is given to HTTP.
          if (socket.remoteAddress !== this.target.address || socket.remotePort !== this.target.port) {
            socket.destroy(); refuse("connect_address_mismatch"); return;
          }
          req!.end(body);
        };
        if (socket.connecting) socket.once("connect", checked); else checked();
      });
      req.on("response", (incoming) => {
        response = incoming;
        incoming.once("error", () => refuse("transport"));
        incoming.once("aborted", () => refuse("transport"));
        if (settled) { incoming.destroy(); return; }
        // Redirects never get a second connection, preserving the checked peer boundary.
        if (incoming.statusCode !== undefined && incoming.statusCode >= HTTP_REDIRECT_MIN && incoming.statusCode < HTTP_REDIRECT_END) { refuse("redirect"); return; }
        if (incoming.statusCode !== HTTP_OK) { refuse("http_status"); return; }
        void read(incoming).then(finish, (error: unknown) => refuse(error instanceof Refused ? error.reason : "invalid_response"));
      });
      signal?.addEventListener("abort", cancel, { once: true });
      if (signal?.aborted) { cancel(); return; }
      const setTimer = this.dependencies.setTimer ?? ((callback: () => void, ms: number) => setTimeout(callback, ms));
      timer = setTimer(() => refuse("timeout"), this.dependencies.timeoutMs ?? LOCAL_CALL_TIMEOUT_MS);
    });
  }
}
