import { CallToolRequestSchema, CallToolResultSchema, InitializeRequestSchema, ListToolsResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { isRecord, parseStrictJsonObject, StrictJsonError } from "../hermes-memory-bridge/strict-json.js";
import { HERMES_TOOL_TIMEOUT_MS, MAX_PUBLIC_FRAME_BYTES, MAX_JSON_NESTING_DEPTH } from "../hermes-memory-bridge/constants.js";

export { HERMES_TOOL_TIMEOUT_MS, MAX_PUBLIC_FRAME_BYTES, isRecord, parseStrictJsonObject, StrictJsonError };
// Must match the client contract in hermes-memory-relay/SEAM.md and RelayProtocolConstants in Core.swift.
export const PREFIX_BYTES = 4; // One u32 big-endian length, excluded from the payload cap.
export const MAX_SOCKET_TAIL_BYTES = MAX_PUBLIC_FRAME_BYTES + PREFIX_BYTES;
export const MAX_MCP_ID_CHARS = 128; // Shim-local ASCII ID ceiling; numeric IDs remain typed.
export const MCP_ENVELOPE_BYTES = Buffer.byteLength('{"jsonrpc":"2.0","id":"","result":}') + MAX_MCP_ID_CHARS;
export const MAX_STDIO_JSON_BYTES = MAX_PUBLIC_FRAME_BYTES + MCP_ENVELOPE_BYTES;
export const MAX_STDIO_LINE_BYTES = MAX_STDIO_JSON_BYTES + Buffer.byteLength("\r\n");
export const STDIO_DEPTH = MAX_JSON_NESTING_DEPTH + 1; // params adds one composite to the relay shape.
export const SHIM_DELIVERY_MARGIN_MS = 2_000; // Reserved response delivery interval inside the Hermes tool wait.
export const SHIM_WRITE_STALL_MS = SHIM_DELIVERY_MARGIN_MS;
export const SHIM_CALL_DEADLINE_MS = HERMES_TOOL_TIMEOUT_MS - SHIM_DELIVERY_MARGIN_MS;
export const SHIM_CONNECT_HELLO_TIMEOUT_MS = 5_000; // CD1a: one bounded local readiness attempt.
export const SHIM_INITIALIZATION_TIMEOUT_MS = 5_000; // CD1b: each abandoned initialization state.
export const HERMES_PROBE_WAIT_MS = 30_000; // Hermes ping request wait, separate from its scheduling interval.
export const SHIM_PING_TIMEOUT_MS = HERMES_PROBE_WAIT_MS - SHIM_DELIVERY_MARGIN_MS;
export const SHIM_CANCEL_SETTLE_MS = 30_000 + 2_000; // Memory batch lock wait plus probe wait, no durability promise.
export const SHIM_EXIT_MARGIN_MS = 500; // Scheduler and process exit reserve within the Python grace.
export const SHIM_STDIN_EOF_EXIT_MS = 2_000 - SHIM_EXIT_MARGIN_MS;
export const SHIM_DISCONNECT_TIMEOUT_MS = SHIM_STDIN_EOF_EXIT_MS;
export const CONTROL_CAP = 8; // Must match controlQueueDepthPerConnection in Core.swift; retain credits until close.
export const PING_CAP = 2; // Must match controlResponseAllowancePerConnection in Core.swift.
export const REGULAR_RECORD_CAP = 1 + 1 + PING_CAP; // Primary, local refusal, ping FIFO.
export const CLIENT_NAME = "sanctuary-hermes-memory-client";
export const RELAY_VERSION = "2026-10-12";
export const VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"] as const;
export const FIXED_SOCKET_PATH = "/Library/Application Support/Sanctuary/HermesMemoryBridge/sockets/memory.sock";
export const TOOL_NAMES = ["memory_insert", "memory_get", "memory_search"] as const;
export const ERRORS = Object.freeze({
  denied: [-32002, "Memory request denied."], busy: [-32003, "Memory request denied."],
  unavailable: [-32004, "Memory service unavailable."], unknown: [-32004, "Memory service unavailable. Outcome unknown."],
  deadline: [-32005, "Memory request timed out. Outcome unknown."],
  parse: [-32700, "Parse error."], invalid: [-32600, "Invalid request."], params: [-32602, "Invalid params."],
  method: [-32601, "Method not found."], internal: [-32603, "Memory service unavailable."],
} as const);
export type ErrorKind = keyof typeof ERRORS;
export type McpId = string | number;
export const validId = (id: unknown): id is McpId => typeof id === "number" ? Number.isSafeInteger(id)
  : typeof id === "string" && /^[A-Za-z0-9._:-]{1,128}$/u.test(id);
export const idKey = (id: McpId): string => `${typeof id}:${id}`;
export function errorLine(id: McpId | null, kind: ErrorKind): Buffer {
  const [code, message] = ERRORS[kind];
  return Buffer.from(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
}
export function resultLine(id: McpId, payload: Buffer): Buffer {
  // Keeping the payload bytes intact preserves the bridge's projection and escaping decisions.
  if (payload.includes(10) || payload.includes(13)) throw new Error("invalid payload");
  const line = Buffer.concat([Buffer.from(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":`), payload, Buffer.from("}\n")]);
  if (line.length > MAX_STDIO_LINE_BYTES) throw new Error("invalid payload");
  return line;
}
export function relayFrame(value: Record<string, unknown>): Buffer {
  const body = Buffer.from(JSON.stringify(value));
  // Validate the actual outbound shape because params and arguments have different nesting budgets.
  if (body.length > MAX_PUBLIC_FRAME_BYTES) throw new Error("invalid frame");
  parseStrictJsonObject(body, MAX_JSON_NESTING_DEPTH);
  const prefix = Buffer.alloc(PREFIX_BYTES); prefix.writeUInt32BE(body.length);
  return Buffer.concat([prefix, body]);
}
export function initializeResult(request: Record<string, unknown>, version: string): Buffer {
  const parsed = InitializeRequestSchema.parse(request);
  const proposal = parsed.params.protocolVersion;
  return Buffer.from(JSON.stringify({ protocolVersion: VERSIONS.find(v => v === proposal) ?? VERSIONS[0],
    capabilities: { tools: {} }, serverInfo: { name: CLIENT_NAME, version } }));
}
export function callParams(request: Record<string, unknown>): { name: string; arguments: Record<string, unknown> } {
  const parsed = CallToolRequestSchema.parse(request);
  return { name: parsed.params.name, arguments: parsed.params.arguments ?? {} };
}

/** Bounded recovery reads the entire rejected line, including an SDK id serialized last. */
export class IdScanner {
  private depth = 0;
  private quoted = false;
  private escaped = false;
  private token = "";
  private overflow = false;
  private phase: "key" | "colon" | "value" | "after" = "key";
  private key = "";
  private seen = false;
  private duplicate = false;
  private candidate: McpId | undefined;
  // Six ASCII bytes per escaped UTF-16 code unit, plus the two string delimiters.
  private static readonly TOKEN_CAP = MAX_MCP_ID_CHARS * 6 + 2;
  private append(byte: number): void {
    if (this.token.length < IdScanner.TOKEN_CAP) this.token += String.fromCharCode(byte);
    else this.overflow = true;
  }
  private capture(): void {
    if (this.key !== "id") return;
    if (this.seen) this.duplicate = true;
    this.seen = true;
    // A truncated numeric token may parse as a different valid ID, so it cannot correlate a reply.
    if (this.overflow) return;
    try { const value: unknown = JSON.parse(this.token); if (validId(value)) this.candidate = value; } catch { /* No correlation without an ID. */ }
  }
  feed(byte: number): void {
    if (this.quoted) {
      if (this.depth === 1) this.append(byte);
      if (this.escaped) this.escaped = false;
      else if (byte === 92) this.escaped = true;
      else if (byte === 34) {
        this.quoted = false;
        if (this.depth === 1) {
          if (this.phase === "key") {
            try { this.key = JSON.parse(this.token) as string; } catch { this.key = ""; }
            this.phase = "colon";
          } else { this.capture(); this.phase = "after"; }
          this.token = ""; this.overflow = false;
        }
      }
      return;
    }
    if (byte === 34) { this.quoted = true; this.token = ""; this.overflow = false; if (this.depth === 1) this.append(byte); return; }
    if (byte === 123 || byte === 91) { this.depth++; return; }
    if (byte === 125 || byte === 93) {
      if (this.depth === 1 && this.phase === "value") this.capture();
      this.depth--; return;
    }
    if (this.depth !== 1) return;
    if (byte === 58 && this.phase === "colon") { this.phase = "value"; return; }
    if (byte === 44) {
      if (this.phase === "value") this.capture();
      this.phase = "key"; this.key = ""; this.token = ""; this.overflow = false; return;
    }
    if (this.phase === "value" && byte !== 32 && byte !== 9 && byte !== 13) this.append(byte);
  }
  get id(): McpId | undefined { return this.duplicate ? undefined : this.candidate; }
}

export type InputLine = { bytes: Buffer; oversize: false; recovered: McpId | undefined }
  | { oversize: true; recovered: McpId | undefined };
/** One line is retained; oversized tails are scanned without retaining their content. */
export class LineReader {
  private bytes = Buffer.alloc(MAX_STDIO_LINE_BYTES);
  private used = 0;
  private oversize = false;
  private scanner = new IdScanner();
  take(byte: number): InputLine | undefined {
    if (byte === 10) {
      const result: InputLine = this.oversize ? { oversize: true, recovered: this.scanner.id }
        : { oversize: false, bytes: Buffer.from(this.bytes.subarray(0, this.used)), recovered: this.scanner.id };
      this.used = 0; this.oversize = false; this.scanner = new IdScanner();
      return result;
    }
    this.scanner.feed(byte);
    // Capacity is checked before copying. A UTF-8 suffix remains inside this byte budget.
    if (this.used >= MAX_STDIO_JSON_BYTES + 1) this.oversize = true;
    if (!this.oversize) this.bytes[this.used++] = byte;
    return undefined;
  }
}

/** Locate JSON member bytes after strict validation; ranges refer to the original buffer. */
export function memberRanges(bytes: Buffer): Map<string, [number, number]> {
  const ranges = new Map<string, [number, number]>();
  let i = 0;
  const space = () => { while ([32, 9, 13, 10].includes(bytes[i])) i++; };
  const stringEnd = () => { i++; while (i < bytes.length) { const b = bytes[i++]; if (b === 92) i++; else if (b === 34) return; } };
  space(); i++; space();
  while (bytes[i] !== 125) {
    const keyStart = i; stringEnd(); const key = JSON.parse(bytes.subarray(keyStart, i).toString()) as string;
    space(); i++; space(); const start = i;
    if (bytes[i] === 34) stringEnd();
    else if (bytes[i] === 123 || bytes[i] === 91) {
      let depth = 0;
      do { const b = bytes[i]; if (b === 34) stringEnd(); else { i++; if (b === 123 || b === 91) depth++; if (b === 125 || b === 93) depth--; } } while (depth > 0);
    } else { while (i < bytes.length && ![44, 125, 32, 9, 13, 10].includes(bytes[i])) i++; }
    ranges.set(key, [start, i]); space(); if (bytes[i] === 44) { i++; space(); } else break;
  }
  return ranges;
}

/** Validate the exact relay catalog and change only each tool's schema-key token. */
export function translatedCatalog(payload: Buffer): Buffer {
  const value = parseStrictJsonObject(payload);
  if (Object.keys(value).length !== 1 || !Array.isArray(value.tools) || value.tools.length !== TOOL_NAMES.length) throw new Error("invalid catalog");
  const names = value.tools.map(tool => isRecord(tool) ? tool.name : null);
  if (!TOOL_NAMES.every(name => names.filter(x => x === name).length === 1)) throw new Error("invalid catalog");
  for (const tool of value.tools) if (!isRecord(tool) || !isRecord(tool.input_schema) || "inputSchema" in tool) throw new Error("invalid catalog");
  // Token depth, rather than a text replacement, confines renaming to tool-level keys.
  const text = payload.toString("utf8");
  let depth = 0; let out = ""; let last = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "\"") {
      const start = i++;
      while (i < text.length) { if (text[i] === "\\") i += 2; else if (text[i++] === "\"") break; else continue; }
      const end = i; i--;
      if (depth === 3 && JSON.parse(text.slice(start, end)) === "input_schema" && /^\s*:/u.test(text.slice(end))) {
        out += text.slice(last, start) + '"inputSchema"'; last = end;
      }
    } else if (ch === "{" || ch === "[") depth++; else if (ch === "}" || ch === "]") depth--;
  }
  const translated = Buffer.from(out + text.slice(last));
  ListToolsResultSchema.parse(parseStrictJsonObject(translated));
  return translated;
}
export function validateCallResult(payload: Buffer): void {
  const value = parseStrictJsonObject(payload);
  // The SDK default for missing content must never manufacture a successful bridge result.
  if (!Array.isArray(value.content)) throw new Error("invalid result");
  CallToolResultSchema.parse(value);
}
