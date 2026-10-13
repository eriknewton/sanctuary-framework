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
  | {
    readonly kind: "public_rejection";
    readonly reason: string;
    readonly disposition: "deny" | "silent" | "close";
    readonly frameType?: string;
    readonly requestId?: string;
  };

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

export type HermesWireEncodeErrorCode =
  | "invalid_connection_id"
  | "invalid_nonce"
  | "invalid_request_id"
  | "invalid_encoder_envelope"
  | "private_frame_over_cap";

export class HermesWireEncodeError extends Error {
  constructor(
    readonly code: HermesWireEncodeErrorCode,
    message: string = code,
  ) {
    super(message);
    this.name = "HermesWireEncodeError";
  }
}

type FieldValidator = (value: unknown) => boolean;

type ObjectSchema = {
  readonly required: readonly string[];
  readonly optional?: readonly string[];
  readonly fields: Readonly<Record<string, FieldValidator>>;
  readonly refine?: (value: Record<string, unknown>) => boolean;
};

type SchemaTable = Readonly<Record<string, ObjectSchema>>;

const stringField: FieldValidator = (value) => typeof value === "string";
const objectField: FieldValidator = (value) => isRecord(value);
const literal = (expected: string): FieldValidator => (value) => value === expected;

const requestIdField: FieldValidator = (value) => isRequestId(value);
const connectionIdField: FieldValidator = (value) => isConnectionId(value);
const nonceField: FieldValidator = (value) => typeof value === "string" && NONCE_PATTERN.test(value);
const standardBase64Field: FieldValidator = (value) => typeof value === "string" && decodeStandardBase64(value) !== null;
const searchLimitField: FieldValidator = (value) =>
  typeof value === "number" && Number.isInteger(value) && value >= MIN_SEARCH_LIMIT && value <= MAX_SEARCH_LIMIT;
const stringArrayField: FieldValidator = (value) => Array.isArray(value) && value.every((entry) => typeof entry === "string");
const taintField: FieldValidator = (value) => isTaint(value);

// This table is the parser and encoder agreement point; every frame side uses the same keys and validators.
export const HERMES_MEMORY_WIRE_SCHEMAS = Object.freeze({
  relayToNode: Object.freeze({
    accepted: schema(["type", "connection_id"], { type: literal("accepted"), connection_id: connectionIdField }),
    frame: schema(["type", "connection_id", "frame_b64"], {
      type: literal("frame"),
      connection_id: connectionIdField,
      frame_b64: standardBase64Field,
    }),
    closed: schema(["type", "connection_id"], { type: literal("closed"), connection_id: connectionIdField }),
    probe_reply: schema(["type", "connection_id", "nonce"], {
      type: literal("probe_reply"),
      connection_id: connectionIdField,
      nonce: nonceField,
    }),
    relay_shutdown: schema(["type"], { type: literal("relay_shutdown") }),
  } satisfies SchemaTable),
  nodeToRelay: Object.freeze({
    ready: schema(["type"], { type: literal("ready") }),
    probe: schema(["type", "connection_id", "nonce"], {
      type: literal("probe"),
      connection_id: connectionIdField,
      nonce: nonceField,
    }),
    response: schema(["type", "connection_id", "request_id", "result_b64"], {
      type: literal("response"),
      connection_id: connectionIdField,
      request_id: requestIdField,
      result_b64: standardBase64Field,
    }),
    close: schema(["type", "connection_id"], { type: literal("close"), connection_id: connectionIdField }),
  } satisfies SchemaTable),
  publicInbound: Object.freeze({
    hello: schema(["type", "request_id", "protocol_version", "client_name"], {
      type: literal("hello"),
      request_id: requestIdField,
      protocol_version: stringField,
      client_name: stringField,
    }),
    tools_list: schema(["type", "request_id"], { type: literal("tools_list"), request_id: requestIdField }),
    tools_call: schema(["type", "request_id", "name", "arguments"], {
      type: literal("tools_call"),
      request_id: requestIdField,
      name: stringField,
      arguments: objectField,
    }),
    cancel: schema(["type", "mcp_request_id"], { type: literal("cancel"), mcp_request_id: requestIdField }),
    shutdown: schema(["type"], { type: literal("shutdown") }),
    ping: schema(["type"], { type: literal("ping") }),
  } satisfies SchemaTable),
  publicOutbound: Object.freeze({
    result: schema(["type", "request_id", "payload"], {
      type: literal("result"),
      request_id: requestIdField,
      payload: objectField,
    }),
    error: schema(["type", "request_id", "message"], {
      type: literal("error"),
      request_id: requestIdField,
      message: stringField,
    }),
    pong: schema(["type"], { type: literal("pong") }),
  } satisfies SchemaTable),
  toolArguments: Object.freeze({
    memory_insert: schema(["text", "taint"], {
      text: stringField,
      taint: taintField,
      tags: stringArrayField,
      passage_id: stringField,
    }, ["tags", "passage_id"]),
    memory_get: schema(["passage_id"], { passage_id: stringField }),
    memory_search: schema([], {
      text: stringField,
      query: stringField,
      tag: stringField,
      limit: searchLimitField,
    }, ["text", "query", "tag", "limit"], (args) => {
      const hasText = typeof args.text === "string";
      const hasQuery = typeof args.query === "string";
      return hasText !== hasQuery;
    }),
  } satisfies SchemaTable),
});

export function parseRelayToNode(bytes: Uint8Array): RelayToNodeParseResult {
  let envelope: Record<string, unknown>;
  try {
    envelope = parseStrictJsonObject(bytes);
  } catch {
    return fatal("invalid private JSON");
  }
  const type = envelope.type;
  if (typeof type !== "string") return fatal("missing private frame type");
  const relaySchema = getSchema(HERMES_MEMORY_WIRE_SCHEMAS.relayToNode, type);
  if (relaySchema === undefined) return fatal("unknown relay frame type");
  // Exact schema validation is the fail-closed boundary between relay bytes and typed bridge frames.
  if (!validateObjectSchema(envelope, relaySchema)) return fatal("unexpected private frame fields");

  switch (type) {
    case "accepted":
      return { kind: "ok", frame: { kind: "accepted", connectionId: envelope.connection_id as string } };
    case "closed":
      return { kind: "ok", frame: { kind: "closed", connectionId: envelope.connection_id as string } };
    case "probe_reply":
      return {
        kind: "ok",
        frame: { kind: "probe_reply", connectionId: envelope.connection_id as string, nonce: envelope.nonce as string },
      };
    case "relay_shutdown":
      return { kind: "ok", frame: { kind: "relay_shutdown" } };
    case "frame":
      return parseFrameEnvelope(envelope);
  }
  return fatal("unknown relay frame type");
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
  if (typeof type !== "string") return rejectPublic("missing public frame type", frame);
  const publicSchema = getSchema(HERMES_MEMORY_WIRE_SCHEMAS.publicInbound, type);
  if (publicSchema === undefined) return rejectPublic("public frame type is not forwarded to Node", frame);
  if (!validateObjectSchema(frame, publicSchema)) return rejectPublic("invalid public frame fields", frame);

  switch (type) {
    case "hello":
      return {
        kind: "ok",
        frame: {
          kind: "hello",
          requestId: frame.request_id as string,
          protocolVersion: frame.protocol_version as string,
          clientName: frame.client_name as string,
        },
      };
    case "tools_list":
      return { kind: "ok", frame: { kind: "tools_list", requestId: frame.request_id as string } };
    case "tools_call":
      return parsePublicToolsCall(frame);
    case "cancel":
      return { kind: "ok", frame: { kind: "cancel", mcpRequestId: frame.mcp_request_id as string } };
    case "shutdown":
      return { kind: "ok", frame: { kind: "shutdown" } };
    case "ping":
      return rejectPublic("ping is answered by the relay", frame);
  }
  return rejectPublic("public frame type is not forwarded to Node", frame);
}

export function encodeNodeToRelay(input: NodeToRelayInput): Buffer {
  switch (input.type) {
    case "ready":
      return encodeJsonEnvelope({ type: "ready" }, HERMES_MEMORY_WIRE_SCHEMAS.nodeToRelay.ready);
    case "probe":
      requireConnectionId(input.connectionId);
      requireNonce(input.nonce);
      return encodeJsonEnvelope(
        { type: "probe", connection_id: input.connectionId, nonce: input.nonce },
        HERMES_MEMORY_WIRE_SCHEMAS.nodeToRelay.probe,
      );
    case "close":
      requireConnectionId(input.connectionId);
      return encodeJsonEnvelope(
        { type: "close", connection_id: input.connectionId },
        HERMES_MEMORY_WIRE_SCHEMAS.nodeToRelay.close,
      );
    case "response":
      requireConnectionId(input.connectionId);
      requireRequestId(input.requestId);
      return encodeResponse(input.connectionId, input.requestId, input.publicPayloadBytes);
  }
}

export function buildDeniedPublicResponseBytes(requestId: string): Uint8Array {
  requireRequestId(requestId);
  const envelope = {
    type: "error",
    request_id: requestId,
    message: HERMES_MEMORY_DENIAL,
  };
  if (!validateObjectSchema(envelope, HERMES_MEMORY_WIRE_SCHEMAS.publicOutbound.error)) {
    throw new HermesWireEncodeError("invalid_encoder_envelope", "fixed denial violates public error schema");
  }
  return Buffer.from(JSON.stringify(envelope), "utf8");
}

export function decodeStandardBase64(value: string): Uint8Array | null {
  if (!STANDARD_BASE64_PATTERN.test(value) || value.length % 4 !== 0) return null;
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) return null;
  return decoded;
}

function parseFrameEnvelope(envelope: Record<string, unknown>): RelayToNodeParseResult {
  const publicBytes = decodeStandardBase64(envelope.frame_b64 as string);
  // The relay already bounded public bytes, but Node repeats the cap before handing bytes to the public parser.
  if (publicBytes === null || publicBytes.byteLength > MAX_PUBLIC_FRAME_BYTES) {
    return fatal("invalid public frame encoding");
  }
  return {
    kind: "ok",
    frame: {
      kind: "frame",
      connectionId: envelope.connection_id as string,
      publicBytes,
      publicFrame: parsePublicFrame(publicBytes),
    },
  };
}

function parsePublicToolsCall(frame: Record<string, unknown>): PublicFrameParseResult {
  const name = frame.name as string;
  if (!isHermesMemoryToolName(name)) return rejectPublic("invalid tool name", frame);
  const parsedArguments = parseToolArguments(name, frame.arguments as Record<string, unknown>);
  if (parsedArguments === null) return rejectPublic("invalid tool arguments", frame);
  return {
    kind: "ok",
    frame: {
      kind: "tools_call",
      requestId: frame.request_id as string,
      name,
      arguments: parsedArguments,
    },
  };
}

function parseToolArguments(name: HermesMemoryToolName, args: Record<string, unknown>): HermesMemoryToolArguments | null {
  const toolSchema = HERMES_MEMORY_WIRE_SCHEMAS.toolArguments[name];
  if (!validateObjectSchema(args, toolSchema)) return null;
  if (name === "memory_insert") {
    return {
      text: args.text as string,
      taint: args.taint as "user_content" | "agent_derived_clean" | "system_generated",
      ...(args.tags === undefined ? {} : { tags: args.tags as readonly string[] }),
      ...(args.passage_id === undefined ? {} : { passage_id: args.passage_id as string }),
    };
  }
  if (name === "memory_get") return { passage_id: args.passage_id as string };
  return {
    ...(args.text === undefined ? {} : { text: args.text as string }),
    ...(args.query === undefined ? {} : { query: args.query as string }),
    ...(args.tag === undefined ? {} : { tag: args.tag as string }),
    ...(args.limit === undefined ? {} : { limit: args.limit as number }),
  };
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
  }, HERMES_MEMORY_WIRE_SCHEMAS.nodeToRelay.response);
}

function shouldUseDenial(requestId: string, publicPayloadBytes: Uint8Array): boolean {
  if (publicPayloadBytes.byteLength > MAX_RESULT_FRAME_BYTES) return true;
  let parsed: Record<string, unknown>;
  try {
    parsed = parseStrictJsonObject(publicPayloadBytes);
  } catch {
    return true;
  }
  const type = parsed.type;
  if (type !== "result" && type !== "error") return true;
  const publicSchema = HERMES_MEMORY_WIRE_SCHEMAS.publicOutbound[type];
  // Node owns the complete public result and error shape because the relay checks only type and request_id.
  return !validateObjectSchema(parsed, publicSchema) || parsed.request_id !== requestId;
}

function encodeJsonEnvelope(envelope: Record<string, unknown>, schemaForType: ObjectSchema): Buffer {
  if (!validateObjectSchema(envelope, schemaForType)) {
    throw new HermesWireEncodeError("invalid_encoder_envelope", "Node-to-relay envelope violates shared schema");
  }
  const payload = Buffer.from(JSON.stringify(envelope), "utf8");
  if (payload.byteLength > MAX_PRIVATE_FRAME_BYTES) {
    throw new HermesWireEncodeError("private_frame_over_cap", "Hermes memory private frame exceeds relay cap");
  }
  return encodePrivateFrame(payload);
}

function schema(
  required: readonly string[],
  fields: Readonly<Record<string, FieldValidator>>,
  optional: readonly string[] = [],
  refine?: (value: Record<string, unknown>) => boolean,
): ObjectSchema {
  return Object.freeze({ required, optional, fields, refine });
}

function validateObjectSchema(value: Record<string, unknown>, objectSchema: ObjectSchema): boolean {
  const allowed = new Set([...objectSchema.required, ...(objectSchema.optional ?? [])]);
  const actual = Object.keys(value);
  if (actual.some((key) => !allowed.has(key))) return false;
  if (objectSchema.required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) return false;
  for (const key of actual) {
    const validator = objectSchema.fields[key];
    if (validator === undefined || !validator(value[key])) return false;
  }
  return objectSchema.refine?.(value) ?? true;
}

function getSchema(table: SchemaTable, type: string): ObjectSchema | undefined {
  return table[type];
}

function isRequestId(value: unknown): value is string {
  return typeof value === "string" && REQUEST_ID_PATTERN.test(value);
}

function isHermesMemoryToolName(value: string): value is HermesMemoryToolName {
  return value === "memory_insert" || value === "memory_get" || value === "memory_search";
}

function requireRequestId(value: string): void {
  if (!isRequestId(value)) throw new HermesWireEncodeError("invalid_request_id", "invalid request id");
}

function isConnectionId(value: unknown): value is string {
  if (typeof value !== "string" || !CONNECTION_ID_PATTERN.test(value) || value.length > MAX_CONNECTION_ID_BYTES) {
    return false;
  }
  const counter = BigInt(value.slice(1));
  return counter > 0n && counter <= 18_446_744_073_709_551_615n; // 18446744073709551615 is the maximum decimal u64 in hermes-memory-relay/SEAM.md.
}

function requireConnectionId(value: string): void {
  if (!isConnectionId(value)) throw new HermesWireEncodeError("invalid_connection_id", "invalid connection id");
}

function requireNonce(value: string): void {
  if (!NONCE_PATTERN.test(value)) throw new HermesWireEncodeError("invalid_nonce", "invalid probe nonce");
}

function isTaint(value: unknown): value is "user_content" | "agent_derived_clean" | "system_generated" {
  return value === "user_content" || value === "agent_derived_clean" || value === "system_generated";
}

function fatal(reason: string): RelayToNodeParseResult {
  return { kind: "fatal", reason };
}

function rejectPublic(reason: string, frame?: Record<string, unknown>): PublicFrameParseResult {
  const frameType = typeof frame?.type === "string" ? frame.type : undefined;
  if (frameType === "hello" || frameType === "tools_list" || frameType === "tools_call") {
    const requestId = isRequestId(frame?.request_id) ? frame.request_id : undefined;
    return requestId === undefined
      ? { kind: "public_rejection", reason, disposition: "close", frameType }
      : { kind: "public_rejection", reason, disposition: "deny", frameType, requestId };
  }
  if (frameType === "cancel" || frameType === "shutdown" || frameType === "ping") {
    return { kind: "public_rejection", reason, disposition: "silent", frameType };
  }
  return { kind: "public_rejection", reason, disposition: "close", ...(frameType === undefined ? {} : { frameType }) };
}
