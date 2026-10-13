import { Buffer } from "node:buffer";

import {
  CONNECTION_ID_PATTERN,
  HERMES_MEMORY_DENIAL,
  MAX_CONNECTION_ID_BYTES,
  MAX_PRIVATE_FRAME_BYTES,
  MAX_PUBLIC_FRAME_BYTES,
  MAX_RESULT_FRAME_BYTES,
  MAX_SEARCH_LIMIT,
  MIN_SEARCH_LIMIT,
  NONCE_PATTERN,
  REQUEST_ID_PATTERN,
  STANDARD_BASE64_PATTERN,
} from "./constants.js";
import { encodePrivateFrame } from "./framing.js";
import { isRecord, parseStrictJsonObject } from "./strict-json.js";

export type PublicFrame =
  | { readonly kind: "hello"; readonly requestId: string; readonly protocolVersion: string; readonly clientName: string }
  | { readonly kind: "tools_list"; readonly requestId: string }
  | { readonly kind: "tools_call"; readonly requestId: string; readonly name: HermesMemoryToolName; readonly arguments: HermesMemoryToolArguments }
  | { readonly kind: "cancel"; readonly mcpRequestId: string }
  | { readonly kind: "shutdown" };

export type HermesMemoryToolName = "memory_insert" | "memory_get" | "memory_search";

export type HermesMemoryToolArguments =
  | { readonly text: string; readonly taint: "user_content" | "agent_derived_clean" | "system_generated"; readonly tags?: readonly string[]; readonly passage_id?: string }
  | { readonly passage_id: string }
  | { readonly text?: string; readonly query?: string; readonly tag?: string; readonly limit?: number };

export type PublicFrameParseResult =
  | { readonly kind: "ok"; readonly frame: PublicFrame }
  | { readonly kind: "public_rejection"; readonly reason: string };

export type RelayToNodeFrame =
  | { readonly kind: "accepted"; readonly connectionId: string }
  | { readonly kind: "frame"; readonly connectionId: string; readonly publicBytes: Uint8Array; readonly publicFrame: PublicFrameParseResult }
  | { readonly kind: "closed"; readonly connectionId: string }
  | { readonly kind: "probe_reply"; readonly connectionId: string; readonly nonce: string }
  | { readonly kind: "relay_shutdown" };

export type RelayToNodeParseResult =
  | { readonly kind: "ok"; readonly frame: RelayToNodeFrame }
  | { readonly kind: "fatal"; readonly reason: string };

export type NodeToRelayInput =
  | { readonly type: "ready" }
  | { readonly type: "probe"; readonly connectionId: string; readonly nonce: string }
  | { readonly type: "response"; readonly connectionId: string; readonly requestId: string; readonly publicPayloadBytes: Uint8Array }
  | { readonly type: "close"; readonly connectionId: string };

export function parseRelayToNode(bytes: Uint8Array): RelayToNodeParseResult {
  let envelope: Record<string, unknown>;
  try {
    envelope = parseStrictJsonObject(bytes);
  } catch {
    return fatal("invalid private JSON");
  }
  const type = envelope.type;
  if (typeof type !== "string") return fatal("missing private frame type");
  switch (type) {
    case "accepted":
      return parseConnectionEnvelope(envelope, "accepted");
    case "closed":
      return parseConnectionEnvelope(envelope, "closed");
    case "probe_reply":
      return parseProbeReply(envelope);
    case "relay_shutdown":
      return parseRelayShutdown(envelope);
    case "frame":
      return parseFrameEnvelope(envelope);
    default:
      return fatal("unknown relay frame type");
  }
}

export function parsePublicFrame(bytes: Uint8Array): PublicFrameParseResult {
  if (bytes.byteLength > MAX_PUBLIC_FRAME_BYTES) return rejectPublic("public frame exceeds cap");
  let frame: Record<string, unknown>;
  try {
    frame = parseStrictJsonObject(bytes);
  } catch {
    return rejectPublic("invalid public JSON");
  }
  const type = frame.type;
  if (typeof type !== "string") return rejectPublic("missing public frame type");
  switch (type) {
    case "hello":
      return parsePublicHello(frame);
    case "tools_list":
      return parsePublicToolsList(frame);
    case "tools_call":
      return parsePublicToolsCall(frame);
    case "cancel":
      return parsePublicCancel(frame);
    case "shutdown":
      return parsePublicShutdown(frame);
    default:
      return rejectPublic("public frame type is not forwarded to Node");
  }
}

export function encodeNodeToRelay(input: NodeToRelayInput): Buffer {
  switch (input.type) {
    case "ready":
      return encodeJsonEnvelope({ type: "ready" });
    case "probe":
      requireConnectionId(input.connectionId);
      requireNonce(input.nonce);
      return encodeJsonEnvelope({ type: "probe", connection_id: input.connectionId, nonce: input.nonce });
    case "close":
      requireConnectionId(input.connectionId);
      return encodeJsonEnvelope({ type: "close", connection_id: input.connectionId });
    case "response":
      requireConnectionId(input.connectionId);
      requireRequestId(input.requestId);
      return encodeResponse(input.connectionId, input.requestId, input.publicPayloadBytes);
  }
}

export function buildDeniedPublicResponseBytes(requestId: string): Uint8Array {
  requireRequestId(requestId);
  return Buffer.from(JSON.stringify({
    type: "error",
    request_id: requestId,
    message: HERMES_MEMORY_DENIAL,
  }), "utf8");
}

export function decodeStandardBase64(value: string): Uint8Array | null {
  if (!STANDARD_BASE64_PATTERN.test(value) || value.length % 4 !== 0) return null;
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) return null;
  return decoded;
}

function parseConnectionEnvelope(
  envelope: Record<string, unknown>,
  type: "accepted" | "closed",
): RelayToNodeParseResult {
  if (!hasExactKeys(envelope, ["type", "connection_id"])) return fatal("unexpected private frame fields");
  if (!isConnectionId(envelope.connection_id)) return fatal("invalid connection id");
  return { kind: "ok", frame: { kind: type, connectionId: envelope.connection_id } };
}

function parseProbeReply(envelope: Record<string, unknown>): RelayToNodeParseResult {
  if (!hasExactKeys(envelope, ["type", "connection_id", "nonce"])) return fatal("unexpected private frame fields");
  if (!isConnectionId(envelope.connection_id)) return fatal("invalid connection id");
  if (typeof envelope.nonce !== "string" || !NONCE_PATTERN.test(envelope.nonce)) {
    return fatal("invalid probe nonce");
  }
  return { kind: "ok", frame: { kind: "probe_reply", connectionId: envelope.connection_id, nonce: envelope.nonce } };
}

function parseRelayShutdown(envelope: Record<string, unknown>): RelayToNodeParseResult {
  if (!hasExactKeys(envelope, ["type"])) return fatal("unexpected private frame fields");
  return { kind: "ok", frame: { kind: "relay_shutdown" } };
}

function parseFrameEnvelope(envelope: Record<string, unknown>): RelayToNodeParseResult {
  if (!hasExactKeys(envelope, ["type", "connection_id", "frame_b64"])) return fatal("unexpected private frame fields");
  if (!isConnectionId(envelope.connection_id)) return fatal("invalid connection id");
  if (typeof envelope.frame_b64 !== "string") return fatal("invalid public frame encoding");
  const publicBytes = decodeStandardBase64(envelope.frame_b64);
  if (publicBytes === null || publicBytes.byteLength > MAX_PUBLIC_FRAME_BYTES) {
    return fatal("invalid public frame encoding");
  }
  return {
    kind: "ok",
    frame: {
      kind: "frame",
      connectionId: envelope.connection_id,
      publicBytes,
      publicFrame: parsePublicFrame(publicBytes),
    },
  };
}

function parsePublicHello(frame: Record<string, unknown>): PublicFrameParseResult {
  if (!hasExactKeys(frame, ["type", "request_id", "protocol_version", "client_name"])) {
    return rejectPublic("unexpected hello fields");
  }
  if (!isRequestId(frame.request_id) || typeof frame.protocol_version !== "string" || typeof frame.client_name !== "string") {
    return rejectPublic("invalid hello fields");
  }
  return {
    kind: "ok",
    frame: {
      kind: "hello",
      requestId: frame.request_id,
      protocolVersion: frame.protocol_version,
      clientName: frame.client_name,
    },
  };
}

function parsePublicToolsList(frame: Record<string, unknown>): PublicFrameParseResult {
  if (!hasExactKeys(frame, ["type", "request_id"])) return rejectPublic("unexpected tools_list fields");
  if (!isRequestId(frame.request_id)) return rejectPublic("invalid request id");
  return { kind: "ok", frame: { kind: "tools_list", requestId: frame.request_id } };
}

function parsePublicToolsCall(frame: Record<string, unknown>): PublicFrameParseResult {
  if (!hasExactKeys(frame, ["type", "request_id", "name", "arguments"])) {
    return rejectPublic("unexpected tools_call fields");
  }
  if (!isRequestId(frame.request_id) || typeof frame.name !== "string" || !isRecord(frame.arguments)) {
    return rejectPublic("invalid tools_call fields");
  }
  if (!isHermesMemoryToolName(frame.name)) return rejectPublic("invalid tool name");
  const parsedArguments = parseToolArguments(frame.name, frame.arguments);
  if (parsedArguments === null) return rejectPublic("invalid tool arguments");
  return {
    kind: "ok",
    frame: {
      kind: "tools_call",
      requestId: frame.request_id,
      name: frame.name,
      arguments: parsedArguments,
    },
  };
}

function parsePublicCancel(frame: Record<string, unknown>): PublicFrameParseResult {
  if (!hasExactKeys(frame, ["type", "mcp_request_id"])) return rejectPublic("unexpected cancel fields");
  if (!isRequestId(frame.mcp_request_id)) return rejectPublic("invalid cancel id");
  return { kind: "ok", frame: { kind: "cancel", mcpRequestId: frame.mcp_request_id } };
}

function parsePublicShutdown(frame: Record<string, unknown>): PublicFrameParseResult {
  if (!hasExactKeys(frame, ["type"])) return rejectPublic("unexpected shutdown fields");
  return { kind: "ok", frame: { kind: "shutdown" } };
}

function parseToolArguments(name: HermesMemoryToolName, args: Record<string, unknown>): HermesMemoryToolArguments | null {
  if (name === "memory_insert") {
    if (!hasOnlyKeys(args, ["text", "taint", "tags", "passage_id"])) return null;
    if (typeof args.text !== "string" || !isTaint(args.taint)) return null;
    if (args.tags !== undefined && !isStringArray(args.tags)) return null;
    if (args.passage_id !== undefined && typeof args.passage_id !== "string") return null;
    return {
      text: args.text,
      taint: args.taint,
      ...(args.tags === undefined ? {} : { tags: args.tags }),
      ...(args.passage_id === undefined ? {} : { passage_id: args.passage_id }),
    };
  }
  if (name === "memory_get") {
    if (!hasExactKeys(args, ["passage_id"]) || typeof args.passage_id !== "string") return null;
    return { passage_id: args.passage_id };
  }
  if (name === "memory_search") {
    if (!hasOnlyKeys(args, ["text", "query", "tag", "limit"])) return null;
    const text = args.text;
    const query = args.query;
    const tag = args.tag;
    const limit = args.limit;
    if (typeof text !== "string" && typeof query !== "string") return null;
    if (typeof text === "string" && typeof query === "string") return null;
    if (tag !== undefined && typeof tag !== "string") return null;
    if (limit !== undefined && (typeof limit !== "number" || !Number.isInteger(limit) || limit < MIN_SEARCH_LIMIT || limit > MAX_SEARCH_LIMIT)) {
      return null;
    }
    const textValue = typeof text === "string" ? text : undefined;
    const queryValue = typeof query === "string" ? query : undefined;
    return {
      ...(textValue === undefined ? {} : { text: textValue }),
      ...(queryValue === undefined ? {} : { query: queryValue }),
      ...(tag === undefined ? {} : { tag }),
      ...(limit === undefined ? {} : { limit }),
    };
  }
  return null;
}

function encodeResponse(connectionId: string, requestId: string, publicPayloadBytes: Uint8Array): Buffer {
  const resultBytes = shouldUseDenial(requestId, publicPayloadBytes)
    ? buildDeniedPublicResponseBytes(requestId)
    : publicPayloadBytes;
  return encodeJsonEnvelope({
    type: "response",
    connection_id: connectionId,
    request_id: requestId,
    result_b64: Buffer.from(resultBytes).toString("base64"),
  });
}

function shouldUseDenial(requestId: string, publicPayloadBytes: Uint8Array): boolean {
  if (publicPayloadBytes.byteLength > MAX_RESULT_FRAME_BYTES) return true;
  let parsed: Record<string, unknown>;
  try {
    parsed = parseStrictJsonObject(publicPayloadBytes);
  } catch {
    return true;
  }
  return !hasOnlyKeys(parsed, ["type", "request_id", "payload", "message"]) ||
    (parsed.type !== "result" && parsed.type !== "error") ||
    parsed.request_id !== requestId;
}

function encodeJsonEnvelope(envelope: Record<string, unknown>): Buffer {
  const payload = Buffer.from(JSON.stringify(envelope), "utf8");
  if (payload.byteLength > MAX_PRIVATE_FRAME_BYTES) {
    throw new Error("Hermes memory private frame exceeds relay cap");
  }
  return encodePrivateFrame(payload);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function isRequestId(value: unknown): value is string {
  return typeof value === "string" && REQUEST_ID_PATTERN.test(value);
}

function isHermesMemoryToolName(value: string): value is HermesMemoryToolName {
  return value === "memory_insert" || value === "memory_get" || value === "memory_search";
}

function requireRequestId(value: string): void {
  if (!isRequestId(value)) throw new Error("invalid request id");
}

function isConnectionId(value: unknown): value is string {
  if (typeof value !== "string" || !CONNECTION_ID_PATTERN.test(value) || value.length > MAX_CONNECTION_ID_BYTES) {
    return false;
  }
  const counter = BigInt(value.slice(1));
  return counter > 0n && counter <= 18_446_744_073_709_551_615n; // 18446744073709551615 is the maximum decimal u64 in hermes-memory-relay/SEAM.md.
}

function requireConnectionId(value: string): void {
  if (!isConnectionId(value)) throw new Error("invalid connection id");
}

function requireNonce(value: string): void {
  if (!NONCE_PATTERN.test(value)) throw new Error("invalid probe nonce");
}

function isTaint(value: unknown): value is "user_content" | "agent_derived_clean" | "system_generated" {
  return value === "user_content" || value === "agent_derived_clean" || value === "system_generated";
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function fatal(reason: string): RelayToNodeParseResult {
  return { kind: "fatal", reason };
}

function rejectPublic(reason: string): PublicFrameParseResult {
  return { kind: "public_rejection", reason };
}
