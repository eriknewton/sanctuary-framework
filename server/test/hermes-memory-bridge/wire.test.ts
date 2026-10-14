import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_WIRE_SCHEMAS,
  LENGTH_PREFIX_BYTES,
  MAX_JSON_NESTING_DEPTH,
  MAX_PRIVATE_FRAME_BYTES,
  MAX_PUBLIC_FRAME_BYTES,
  MAX_RESULT_FRAME_BYTES,
  PrivateFrameError,
  PrivateFrameDecoder,
  buildDeniedPublicResponseBytes,
  decodeStandardBase64,
  encodeNodeToRelay,
  encodePrivateFrame,
  parsePublicFrame,
  parseRelayToNode,
  parseStrictJsonObject,
} from "../../src/hermes-memory-bridge/index.js";
import type {
  NodeToRelayInput,
  PublicFrameParseResult,
} from "../../src/hermes-memory-bridge/index.js";
import { HERMES_MEMORY_WIRE_STATE_DEPENDENT_VECTORS } from "./fixture-state-vectors.js";

type FixtureEntry = {
  readonly name: string;
  readonly direction?: string;
  readonly channel?: string;
  readonly frame?: Record<string, unknown>;
  readonly expected_action: string;
  readonly bytes_hex?: string;
  readonly then_bytes_hex?: string;
};

type FixtureSurface = "publicOrClient" | "nodeToRelay" | "relayToNode";
type PublicExpectedAction = "accept" | "poison_connection";
type FixtureAssertionContext = {
  readonly section: string;
  consume: () => void;
};
type FixtureAssertion = (vector: FixtureEntry, context: FixtureAssertionContext) => void;
type PublicStreamTail =
  | { readonly kind: "none" }
  | { readonly kind: "over_cap"; readonly length: number; readonly remainingBytes: number }
  | { readonly kind: "partial_payload"; readonly length: number; readonly payloadBytes: number }
  | { readonly kind: "partial_prefix"; readonly prefixBytes: number };
type PublicStreamFrame = {
  readonly length: number;
  readonly payload: Buffer;
};
type PublicStreamRead = {
  readonly frames: readonly PublicStreamFrame[];
  readonly tail: PublicStreamTail;
};

const fixtureUrl = new URL("./fixtures/relay-frames.json", import.meta.url);
const relayFixtureText = readFileSync(fixtureUrl, "utf8");
const relayFixture = JSON.parse(relayFixtureText) as Readonly<Record<string, readonly FixtureEntry[]>>;

const textEncoder = new TextEncoder();

function jsonBytes(value: Record<string, unknown>): Uint8Array {
  return textEncoder.encode(JSON.stringify(value));
}

function rawFixtureFrameBytes(name: string): Uint8Array {
  const nameNeedle = `"name": ${JSON.stringify(name)}`;
  const nameAt = relayFixtureText.indexOf(nameNeedle);
  if (nameAt < 0) throw new Error(`fixture vector not found: ${name}`);
  const frameAt = relayFixtureText.indexOf("\"frame\"", nameAt);
  if (frameAt < 0) throw new Error(`fixture frame not found: ${name}`);
  const colonAt = relayFixtureText.indexOf(":", frameAt);
  let start = colonAt + 1;
  while (/\s/u.test(relayFixtureText[start] ?? "")) start += 1;
  if (relayFixtureText[start] !== "{") throw new Error(`fixture frame is not an object: ${name}`);

  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < relayFixtureText.length; index += 1) {
    const ch = relayFixtureText[index]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === "\"") inString = false;
      continue;
    }
    if (ch === "\"") inString = true;
    else if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return textEncoder.encode(relayFixtureText.slice(start, index + 1));
    }
  }
  throw new Error(`fixture frame object is incomplete: ${name}`);
}

function privateBytesForFixture(vector: FixtureEntry): Buffer {
  if (vector.bytes_hex !== undefined) return Buffer.from(vector.bytes_hex, "hex");
  return encodePrivateFrame(rawFixtureFrameBytes(vector.name));
}

function collectFrames(bytes: Uint8Array): Array<Uint8Array | "fatal"> {
  const decoder = new PrivateFrameDecoder();
  decoder.push(bytes);
  const frames: Array<Uint8Array | "fatal"> = [];
  for (;;) {
    const result = decoder.next();
    if (result.kind === "need_more") return frames;
    if (result.kind === "fatal") return [...frames, "fatal"];
    frames.push(result.body);
  }
}

function parsePayload(frame: Buffer): Record<string, unknown> {
  return JSON.parse(frame.subarray(LENGTH_PREFIX_BYTES).toString("utf8")) as Record<string, unknown>;
}

function parseBody(body: Uint8Array): Record<string, unknown> {
  return JSON.parse(Buffer.from(body).toString("utf8")) as Record<string, unknown>;
}

function publicResultBytes(requestId: string, payload: Record<string, unknown>): Uint8Array {
  return jsonBytes({ type: "result", request_id: requestId, payload });
}

function publicErrorBytes(requestId: string): Uint8Array {
  return jsonBytes({ type: "error", request_id: requestId, message: HERMES_MEMORY_DENIAL });
}

function encodedResponsePayloadBytes(requestId: string, publicPayloadBytes: Uint8Array): Buffer {
  const response = parsePayload(encodeNodeToRelay({
    type: "response",
    connectionId: "c1",
    requestId,
    publicPayloadBytes,
  }));
  return Buffer.from(response.result_b64 as string, "base64");
}

function innerResultBytes(vectorName: string): Uint8Array {
  const vector = findFixtureVector(vectorName);
  const frames = collectFrames(privateBytesForFixture(vector));
  const first = frames[0];
  if (first === undefined || first === "fatal") throw new Error(`fixture vector has no private response: ${vectorName}`);
  const envelope = JSON.parse(Buffer.from(first).toString("utf8")) as { result_b64: string };
  return Buffer.from(envelope.result_b64, "base64");
}

function findFixtureVector(name: string): FixtureEntry {
  for (const section of Object.values(relayFixture)) {
    const found = section.find((entry) => entry.name === name);
    if (found !== undefined) return found;
  }
  throw new Error(`fixture vector not found: ${name}`);
}

function allFixtureEntries(): readonly FixtureEntry[] {
  return Object.entries(relayFixture).flatMap(([sectionName, section]) => {
    if (!Array.isArray(section)) throw new Error(`fixture section is not an array: ${sectionName}`);
    return section;
  });
}

function fixtureTotal(): number {
  return Object.values(relayFixture).reduce((total, section) => total + section.length, 0);
}

function fixtureSections(): ReadonlyArray<readonly [string, readonly FixtureEntry[]]> {
  return Object.entries(relayFixture);
}

function fixtureSurface(entry: FixtureEntry): FixtureSurface {
  if (entry.direction === "relayToNode" || entry.channel === "relay_to_node") return "relayToNode";
  if (entry.direction === "nodeToRelay" || entry.channel === "node_to_relay") return "nodeToRelay";
  if (entry.direction === "publicInbound" || entry.direction === "clientOutbound" || entry.channel === "public") {
    return "publicOrClient";
  }
  throw new Error(`fixture vector has unknown channel: ${entry.name}`);
}

function relayToNodeVectors(): readonly FixtureEntry[] {
  return allFixtureEntries().filter((entry) => fixtureSurface(entry) === "relayToNode");
}

function nodeToRelayVectors(): readonly FixtureEntry[] {
  return allFixtureEntries().filter((entry) => fixtureSurface(entry) === "nodeToRelay");
}

function stateDependentNames(): readonly string[] {
  return HERMES_MEMORY_WIRE_STATE_DEPENDENT_VECTORS.map((entry) => entry.name);
}

function isStateDependent(name: string): boolean {
  return stateDependentNames().includes(name);
}

function expectedRelayFrameFromBody(body: Uint8Array): Record<string, unknown> {
  const envelope = parseStrictJsonObject(body);
  switch (envelope.type) {
    case "accepted":
      return { kind: "accepted", connectionId: envelope.connection_id };
    case "closed":
      return { kind: "closed", connectionId: envelope.connection_id };
    case "probe_reply":
      return { kind: "probe_reply", connectionId: envelope.connection_id, nonce: envelope.nonce };
    case "relay_shutdown":
      return { kind: "relay_shutdown" };
    case "frame":
      {
        const publicBytes = decodeStandardBase64(envelope.frame_b64 as string);
        if (publicBytes === null) throw new Error("fixture frame has invalid public bytes");
        return {
          kind: "frame",
          connectionId: envelope.connection_id,
          publicBytes,
          publicFrame: parsePublicFrame(publicBytes),
        };
      }
    default:
      throw new Error("not a typed relay-to-Node frame");
  }
}

function publicActionFromNodeResult(result: PublicFrameParseResult): PublicExpectedAction {
  switch (result.kind) {
    case "ok":
      switch (result.frame.kind) {
        case "hello":
        case "tools_list":
        case "tools_call":
        case "cancel":
        case "shutdown":
          return "accept";
        default: {
          const unreachable: never = result.frame;
          throw new Error(`unhandled public frame kind: ${JSON.stringify(unreachable)}`);
        }
      }
    case "public_rejection":
      switch (result.disposition) {
        case "deny":
        case "close":
          return "poison_connection";
        case "silent":
          // The relay answers ping itself, so Node's silent ping result is the fixture's accepted public behavior.
          return result.frameType === "ping" ? "accept" : "poison_connection";
        default: {
          const unreachable: never = result.disposition;
          throw new Error(`unhandled public disposition: ${String(unreachable)}`);
        }
      }
    default: {
      const unreachable: never = result;
      throw new Error(`unhandled public parse result: ${JSON.stringify(unreachable)}`);
    }
  }
}

function readPublicLengthPrefixedFrames(bytes: Buffer): PublicStreamRead {
  const frames: PublicStreamFrame[] = [];
  let offset = 0;
  while (offset < bytes.byteLength) {
    if (bytes.byteLength - offset < LENGTH_PREFIX_BYTES) {
      return { frames, tail: { kind: "partial_prefix", prefixBytes: bytes.byteLength - offset } };
    }
    const length = bytes.readUInt32BE(offset);
    offset += LENGTH_PREFIX_BYTES;
    if (length > MAX_PUBLIC_FRAME_BYTES) {
      return { frames, tail: { kind: "over_cap", length, remainingBytes: bytes.byteLength - offset } };
    }
    if (bytes.byteLength - offset < length) {
      return { frames, tail: { kind: "partial_payload", length, payloadBytes: bytes.byteLength - offset } };
    }
    frames.push({ length, payload: bytes.subarray(offset, offset + length) });
    offset += length;
  }
  return { frames, tail: { kind: "none" } };
}

function schemaTypeKeys(table: Readonly<Record<string, unknown>>): Set<string> {
  return new Set(Object.keys(table));
}

function allowedSchemaKeys(type: string): Set<string> | undefined {
  const schema = HERMES_MEMORY_WIRE_SCHEMAS.nodeToRelay[type as keyof typeof HERMES_MEMORY_WIRE_SCHEMAS.nodeToRelay];
  if (schema === undefined) return undefined;
  return new Set([...schema.required, ...(schema.optional ?? [])]);
}

function expectDenialFromResponseBytes(requestId: string, publicBytes: Uint8Array): void {
  expect(JSON.parse(encodedResponsePayloadBytes(requestId, publicBytes).toString("utf8"))).toEqual({
    type: "error",
    request_id: requestId,
    message: HERMES_MEMORY_DENIAL,
  });
}

function expectFixedDenialPayload(requestId: string, payload: Uint8Array, label: string): void {
  expect(JSON.parse(Buffer.from(payload).toString("utf8")), label).toEqual({
    type: "error",
    request_id: requestId,
    message: HERMES_MEMORY_DENIAL,
  });
}

function expectExactlyOnePrivateBody(vector: FixtureEntry, bytes = privateBytesForFixture(vector)): Uint8Array {
  const frames = collectFrames(bytes);
  expect(frames, vector.name).toHaveLength(1);
  const body = frames[0];
  expect(body, vector.name).not.toBe("fatal");
  if (body === undefined || body === "fatal") throw new Error(`fixture vector did not decode to one private body: ${vector.name}`);
  return body;
}

function expectEncodedPrivateFrameMatches(vector: FixtureEntry, input: NodeToRelayInput, body: Uint8Array): Buffer {
  const encoded = encodeNodeToRelay(input);
  const encodedBodies = collectFrames(encoded);
  expect(encodedBodies, vector.name).toHaveLength(1);
  expect(encodedBodies[0], vector.name).not.toBe("fatal");
  expect(parsePayload(encoded), vector.name).toEqual(parseBody(body));
  return encoded;
}

function nodeToRelayInputFromEnvelope(envelope: Record<string, unknown>): NodeToRelayInput | undefined {
  switch (envelope.type) {
    case "ready":
      return { type: "ready" };
    case "probe":
      return {
        type: "probe",
        connectionId: envelope.connection_id as string,
        nonce: envelope.nonce as string,
      };
    case "close":
      return { type: "close", connectionId: envelope.connection_id as string };
    case "response":
      if (typeof envelope.result_b64 !== "string") return undefined;
      return {
        type: "response",
        connectionId: envelope.connection_id as string,
        requestId: envelope.request_id as string,
        publicPayloadBytes: Buffer.from(envelope.result_b64, "base64"),
      };
    default:
      return undefined;
  }
}

function expectRelayToNodeAccepted(vector: FixtureEntry): void {
  expect(fixtureSurface(vector), vector.name).toBe("relayToNode");
  const frames = collectFrames(privateBytesForFixture(vector));
  expect(frames.length, vector.name).toBeGreaterThan(0);
  for (const frame of frames) {
    expect(frame, vector.name).not.toBe("fatal");
    if (frame === "fatal") continue;
    const parsed = parseRelayToNode(frame);
    expect(parsed.kind, vector.name).toBe("ok");
    if (parsed.kind === "ok") expect(parsed.frame, vector.name).toEqual(expectedRelayFrameFromBody(frame));
  }
}

function expectRelayToNodeFatal(vector: FixtureEntry): void {
  expect(fixtureSurface(vector), vector.name).toBe("relayToNode");
  const frames = collectFrames(privateBytesForFixture(vector));
  if (frames.length === 1 && frames[0] === "fatal") {
    expect(frames, vector.name).toEqual(["fatal"]);
    return;
  }
  expect(frames.length, vector.name).toBeGreaterThan(0);
  for (const frame of frames) {
    expect(frame, vector.name).not.toBe("fatal");
    if (frame === "fatal") continue;
    const parsed = parseRelayToNode(frame);
    if (isStateDependent(vector.name)) {
      expect(parsed.kind, vector.name).toBe("ok");
    } else {
      expect(parsed.kind, vector.name).toBe("fatal");
    }
  }
}

function expectValidPublicInbound(vector: FixtureEntry): void {
  expect(vector.direction, vector.name).toBe("publicInbound");
  if (vector.frame === undefined) throw new Error(`fixture public frame missing: ${vector.name}`);
  expect(publicActionFromNodeResult(parsePublicFrame(jsonBytes(vector.frame))), vector.name).toBe("accept");
}

function expectPoisonedPublicInbound(vector: FixtureEntry): void {
  expect(vector.direction, vector.name).toBe("publicInbound");
  if (vector.frame === undefined) throw new Error(`fixture public frame missing: ${vector.name}`);
  expect(publicActionFromNodeResult(parsePublicFrame(jsonBytes(vector.frame))), vector.name).toBe("poison_connection");
}

function expectValidClientOutbound(vector: FixtureEntry): void {
  expect(vector.direction, vector.name).toBe("clientOutbound");
  if (vector.frame === undefined) throw new Error(`fixture client frame missing: ${vector.name}`);
  const requestId = typeof vector.frame.request_id === "string" && vector.frame.request_id.length > 0
    ? vector.frame.request_id
    : "mcp-1";
  const rawPublicBytes = rawFixtureFrameBytes(vector.name);
  const encodedPayload = encodedResponsePayloadBytes(requestId, rawPublicBytes);
  if (vector.frame.type === "pong") {
    // Pong is relay-owned client output; Node's response encoder must not forward it as a public result.
    expectFixedDenialPayload(requestId, encodedPayload, vector.name);
    return;
  }
  expect(encodedPayload.equals(Buffer.from(rawPublicBytes)), vector.name).toBe(true);
}

function expectValidNodeToRelay(vector: FixtureEntry): void {
  expect(fixtureSurface(vector), vector.name).toBe("nodeToRelay");
  const body = expectExactlyOnePrivateBody(vector);
  const input = nodeToRelayInputFromEnvelope(parseBody(body));
  expect(input, vector.name).toBeDefined();
  if (input === undefined) return;
  expectEncodedPrivateFrameMatches(vector, input, body);
}

function assertValidAccept(vector: FixtureEntry, context: FixtureAssertionContext): void {
  switch (fixtureSurface(vector)) {
    case "publicOrClient":
      if (vector.direction === "publicInbound") expectValidPublicInbound(vector);
      else expectValidClientOutbound(vector);
      break;
    case "nodeToRelay":
      expectValidNodeToRelay(vector);
      break;
    case "relayToNode":
      expectRelayToNodeAccepted(vector);
      break;
  }
  context.consume();
}

function assertPublicPoison(vector: FixtureEntry, context: FixtureAssertionContext): void {
  expectPoisonedPublicInbound(vector);
  context.consume();
}

function assertNodeToRelayFatal(vector: FixtureEntry, context: FixtureAssertionContext): void {
  expect(fixtureSurface(vector), vector.name).toBe("nodeToRelay");
  const bytes = privateBytesForFixture(vector);
  const frames = collectFrames(bytes);
  if (frames.length === 1 && frames[0] === "fatal") {
    const length = bytes.readUInt32BE(0);
    expect(length, vector.name).toBeGreaterThan(MAX_PRIVATE_FRAME_BYTES);
    expect(() => encodePrivateFrame(Buffer.alloc(length, 0x61)), vector.name).toThrow(PrivateFrameError);
    expect(() => encodePrivateFrame(Buffer.alloc(length, 0x61)), vector.name).toThrow(/cap/u);
    context.consume();
    return;
  }

  const body = expectExactlyOnePrivateBody(vector, bytes);
  const envelope = parseBody(body);
  const input = nodeToRelayInputFromEnvelope(envelope);
  if (input === undefined) {
    expect(schemaTypeKeys(HERMES_MEMORY_WIRE_SCHEMAS.nodeToRelay), vector.name).not.toContain(String(envelope.type));
    context.consume();
    return;
  }

  expect(envelope.type, vector.name).not.toBe("response");
  const encoded = encodeNodeToRelay(input);
  expect(collectFrames(encoded), vector.name).toHaveLength(1);
  expect(parsePayload(encoded), vector.name).not.toEqual(envelope);
  expect(Object.keys(parsePayload(encoded)).filter((key) => !allowedSchemaKeys(String(envelope.type))?.has(key)), vector.name)
    .toEqual([]);
  context.consume();
}

function assertNodeToRelayDeny(vector: FixtureEntry, context: FixtureAssertionContext): void {
  expect(fixtureSurface(vector), vector.name).toBe("nodeToRelay");
  const body = expectExactlyOnePrivateBody(vector);
  const envelope = parseBody(body);
  expect(envelope.type, vector.name).toBe("response");
  const input = nodeToRelayInputFromEnvelope(envelope);
  expect(input, vector.name).toBeDefined();
  if (input === undefined) return;
  const encoded = encodeNodeToRelay(input);
  expect(collectFrames(encoded), vector.name).toHaveLength(1);
  expect(encoded.equals(Buffer.from(privateBytesForFixture(vector))), vector.name).toBe(false);
  const encodedEnvelope = parsePayload(encoded);
  const originalBase64 = envelope.result_b64;
  const encodedBase64 = encodedEnvelope.result_b64;
  expect(typeof encodedBase64, vector.name).toBe("string");
  if (typeof encodedBase64 === "string" && encodedBase64 !== originalBase64) {
    const decoded = Buffer.from(encodedBase64, "base64");
    const parsed = JSON.parse(decoded.toString("utf8")) as Record<string, unknown>;
    const normalizedOnly = typeof originalBase64 === "string" && decodeStandardBase64(originalBase64) === null;
    if (!normalizedOnly) {
      expect(parsed, vector.name).toEqual({
        type: "error",
        request_id: envelope.request_id,
        message: HERMES_MEMORY_DENIAL,
      });
    }
  }
  context.consume();
}

function assertNodeToRelayForward(vector: FixtureEntry, context: FixtureAssertionContext): void {
  expect(fixtureSurface(vector), vector.name).toBe("nodeToRelay");
  const body = expectExactlyOnePrivateBody(vector);
  const envelope = parseBody(body);
  expect(envelope.type, vector.name).toBe("response");
  const input = nodeToRelayInputFromEnvelope(envelope);
  expect(input, vector.name).toBeDefined();
  if (input !== undefined) expectEncodedPrivateFrameMatches(vector, input, body);
  context.consume();
}

function assertCloseThenLateResponseDiscarded(vector: FixtureEntry, context: FixtureAssertionContext): void {
  expect(fixtureSurface(vector), vector.name).toBe("nodeToRelay");
  const firstBody = expectExactlyOnePrivateBody(vector);
  const firstEnvelope = parseBody(firstBody);
  expect(firstEnvelope.type, vector.name).toBe("close");
  const firstInput = nodeToRelayInputFromEnvelope(firstEnvelope);
  expect(firstInput, vector.name).toBeDefined();
  if (firstInput !== undefined) expectEncodedPrivateFrameMatches(vector, firstInput, firstBody);
  expect(vector.then_bytes_hex, vector.name).toEqual(expect.any(String));
  const thenBody = expectExactlyOnePrivateBody(vector, Buffer.from(vector.then_bytes_hex ?? "", "hex"));
  const thenEnvelope = parseBody(thenBody);
  expect(thenEnvelope.type, vector.name).toBe("response");
  const thenInput = nodeToRelayInputFromEnvelope(thenEnvelope);
  expect(thenInput, vector.name).toBeDefined();
  if (thenInput !== undefined) expectEncodedPrivateFrameMatches(vector, thenInput, thenBody);
  context.consume();
}

function publicStreamRead(vector: FixtureEntry): PublicStreamRead {
  expect(vector.frame, vector.name).toBeUndefined();
  expect(vector.bytes_hex, vector.name).toEqual(expect.any(String));
  return readPublicLengthPrefixedFrames(privateBytesForFixture(vector));
}

function expectCompletePublicFrameActions(vector: FixtureEntry, frames: readonly PublicStreamFrame[]): readonly PublicExpectedAction[] {
  return frames.map((frame, index) => {
    const action = publicActionFromNodeResult(parsePublicFrame(frame.payload));
    expect(action, `${vector.name} frame ${index}`).toMatch(/^(accept|poison_connection)$/u);
    return action;
  });
}

function assertPublicRejectBeforePayloadAllocation(vector: FixtureEntry, context: FixtureAssertionContext): void {
  const decoded = publicStreamRead(vector);
  expect(decoded.frames, vector.name).toHaveLength(0);
  expect(decoded.tail, vector.name).toEqual({ kind: "over_cap", length: MAX_PUBLIC_FRAME_BYTES + 1, remainingBytes: 0 });
  context.consume();
}

function assertPublicRetainUntilProbeThenClosed(vector: FixtureEntry, context: FixtureAssertionContext): void {
  const decoded = publicStreamRead(vector);
  expect(decoded.frames, vector.name).toHaveLength(0);
  expect(decoded.tail, vector.name).toEqual({ kind: "partial_payload", length: 32, payloadBytes: 0 });
  context.consume();
}

function assertPublicDecodeAllCompleteFrames(vector: FixtureEntry, context: FixtureAssertionContext): void {
  const decoded = publicStreamRead(vector);
  const frameBodyBytes = 48 * 1_024;
  expect(decoded.frames.map((frame) => frame.length), vector.name).toEqual([frameBodyBytes, frameBodyBytes]);
  expect(decoded.tail, vector.name).toEqual({ kind: "none" });
  expect(expectCompletePublicFrameActions(vector, decoded.frames), vector.name).toEqual(["accept", "accept"]);
  context.consume();
}

function assertPublicDecodePrefixKeepPartialTail(vector: FixtureEntry, context: FixtureAssertionContext): void {
  const decoded = publicStreamRead(vector);
  expect(decoded.frames.map((frame) => frame.length), vector.name).toEqual([MAX_PUBLIC_FRAME_BYTES]);
  expect(decoded.tail, vector.name).toEqual({
    kind: "partial_payload",
    length: MAX_PUBLIC_FRAME_BYTES,
    payloadBytes: LENGTH_PREFIX_BYTES,
  });
  expect(expectCompletePublicFrameActions(vector, decoded.frames), vector.name).toEqual(["accept"]);
  context.consume();
}

function assertPublicStreamPoisonConnection(vector: FixtureEntry, context: FixtureAssertionContext): void {
  const decoded = publicStreamRead(vector);
  expect(decoded.frames, vector.name).toHaveLength(1);
  expect(decoded.tail, vector.name).toEqual({ kind: "none" });
  expect(expectCompletePublicFrameActions(vector, decoded.frames), vector.name).toEqual(["poison_connection"]);
  expect(decoded.frames[0]?.payload.toString("utf8").includes("\"arguments\""), vector.name).toBe(false);
  context.consume();
}

function assertPublicDecodeOneFrame(vector: FixtureEntry, context: FixtureAssertionContext): void {
  const decoded = publicStreamRead(vector);
  expect(decoded.frames, vector.name).toHaveLength(1);
  expect(decoded.tail, vector.name).toEqual({ kind: "none" });
  const actions = expectCompletePublicFrameActions(vector, decoded.frames);
  expect(actions[0], vector.name).toMatch(/^(accept|poison_connection)$/u);
  if (actions[0] === "poison_connection") {
    expect(decoded.frames[0]?.payload.toString("utf8").includes("\"arguments\""), vector.name).toBe(true);
  }
  context.consume();
}

function assertStreamRelayAccept(vector: FixtureEntry, context: FixtureAssertionContext): void {
  expectRelayToNodeAccepted(vector);
  context.consume();
}

function assertRelayDiscardLateProbeReply(vector: FixtureEntry, context: FixtureAssertionContext): void {
  expect(fixtureSurface(vector), vector.name).toBe("relayToNode");
  const frames = collectFrames(privateBytesForFixture(vector));
  expect(frames.length, vector.name).toBeGreaterThan(0);
  for (const frame of frames) {
    expect(frame, vector.name).not.toBe("fatal");
    if (frame === "fatal") continue;
    const parsed = parseRelayToNode(frame);
    expect(parsed.kind, vector.name).toBe("ok");
    if (parsed.kind === "ok") {
      expect(["closed", "probe_reply"], vector.name).toContain(parsed.frame.kind);
    }
  }
  context.consume();
}

function assertRelayFatalBridge(vector: FixtureEntry, context: FixtureAssertionContext): void {
  expectRelayToNodeFatal(vector);
  context.consume();
}

const fixtureDispatch = {
  valid: {
    accept: assertValidAccept,
  },
  malformed: {
    poison_connection: assertPublicPoison,
    fatal_relay_error: assertNodeToRelayFatal,
  },
  wrong_allowlist: {
    poison_connection: assertPublicPoison,
    fatal_relay_error: assertNodeToRelayFatal,
    fatal_bridge: assertRelayFatalBridge,
  },
  stream_cases: {
    reject_before_payload_allocation: assertPublicRejectBeforePayloadAllocation,
    retain_until_probe_then_closed: assertPublicRetainUntilProbeThenClosed,
    decode_all_complete_frames: assertPublicDecodeAllCompleteFrames,
    decode_prefix_keep_partial_tail: assertPublicDecodePrefixKeepPartialTail,
    poison_connection: assertPublicStreamPoisonConnection,
    decode_one_frame: assertPublicDecodeOneFrame,
    decode_response_and_forward: assertNodeToRelayForward,
    decode_response_and_deny: assertNodeToRelayDeny,
    close_then_late_response_discarded: assertCloseThenLateResponseDiscarded,
    fatal_relay_error: assertNodeToRelayFatal,
    accept: assertStreamRelayAccept,
    discard_late_probe_reply: assertRelayDiscardLateProbeReply,
    fatal_bridge: assertRelayFatalBridge,
  },
} satisfies Readonly<Record<string, Readonly<Record<string, FixtureAssertion>>>>;

function dispatchFixtureVector(section: string, vector: FixtureEntry, consume: () => void): void {
  const sectionDispatch = fixtureDispatch[section as keyof typeof fixtureDispatch];
  expect(sectionDispatch, section).toBeDefined();
  if (sectionDispatch === undefined) return;
  const assertion = sectionDispatch[vector.expected_action as keyof typeof sectionDispatch];
  expect(assertion, `${section}:${vector.name}`).toBeDefined();
  if (assertion === undefined) return;
  (assertion as FixtureAssertion)(vector, { section, consume });
}

function assertFixtureVectors(filter: (entry: FixtureEntry) => boolean = () => true): number {
  let consumed = 0;
  for (const [section, vectors] of fixtureSections()) {
    for (const vector of vectors) {
      if (!filter(vector)) continue;
      dispatchFixtureVector(section, vector, () => {
        consumed += 1;
      });
    }
  }
  return consumed;
}

function assertRelayToNodeFixtureVectors(): number {
  return assertFixtureVectors((entry) => fixtureSurface(entry) === "relayToNode");
}

function assertPublicFixtureVectors(): number {
  return assertFixtureVectors((entry) => fixtureSurface(entry) === "publicOrClient");
}

function assertNodeToRelayFixtureVectors(): number {
  return assertFixtureVectors((entry) => fixtureSurface(entry) === "nodeToRelay");
}

function toolsCallWithArrays(count: number, inner: string): Uint8Array {
  return textEncoder.encode(
    `{"type":"tools_call","request_id":"mcp-1","name":"memory_search","arguments":{"text":${"[".repeat(count)}${inner}${"]".repeat(count)}}}`,
  );
}

describe("Hermes memory bridge strict JSON", () => {
  it("rejects duplicate keys at nested depth and after unescaping", () => {
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"outer\":{\"a\":1,\"a\":2}}"))).toThrow(/duplicate/u);
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"a\":1,\"\\u0061\":2}"))).toThrow(/duplicate/u);
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"__proto__\":1,\"\\u005f_proto__\":2}"))).toThrow(/duplicate/u);
  });

  it("keeps proto spelling as an own data property on a null-prototype object", () => {
    const parsed = parseStrictJsonObject(textEncoder.encode("{\"arguments\":{\"__proto__\":{\"text\":\"not inherited\"}}}"));
    const args = parsed.arguments as Record<string, unknown>;
    const descriptor = Object.getOwnPropertyDescriptor(args, "__proto__");
    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(Object.getPrototypeOf(args)).toBeNull();
    expect(descriptor).toMatchObject({ enumerable: true, configurable: true, writable: true });
    expect(descriptor?.value).toEqual({ text: "not inherited" });
    expect(args.text).toBeUndefined();
  });

  it("counts only composite nesting at the seam boundary", () => {
    expect(() => parseStrictJsonObject(toolsCallWithArrays(MAX_JSON_NESTING_DEPTH - 1, ""))).not.toThrow();
    expect(() => parseStrictJsonObject(toolsCallWithArrays(MAX_JSON_NESTING_DEPTH, ""))).toThrow(/nesting/u);
    expect(() => parseStrictJsonObject(toolsCallWithArrays(MAX_JSON_NESTING_DEPTH - 1, "\"alpha\""))).not.toThrow();
    expect(() => parseStrictJsonObject(toolsCallWithArrays(MAX_JSON_NESTING_DEPTH, "\"alpha\""))).toThrow(/nesting/u);
    const topLevelCompositeOver = `{"a":${"[".repeat(MAX_JSON_NESTING_DEPTH + 1)}${"]".repeat(MAX_JSON_NESTING_DEPTH + 1)}}`;
    expect(() => parseStrictJsonObject(textEncoder.encode(topLevelCompositeOver))).toThrow(/nesting/u);
    const nestedObjects = (count: number) =>
      textEncoder.encode(`{"type":"tools_call","request_id":"mcp-1","name":"memory_search","arguments":${"{\"k\":".repeat(count)}{}${"}".repeat(count)}}`);
    expect(() => parseStrictJsonObject(nestedObjects(MAX_JSON_NESTING_DEPTH - 1))).not.toThrow();
    expect(() => parseStrictJsonObject(nestedObjects(MAX_JSON_NESTING_DEPTH))).toThrow(/nesting/u);
  });

  it("refuses unsafe numbers, malformed UTF-8, leading byte-order marks, controls, and trailing bytes", () => {
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"n\":9007199254740992}"))).toThrow(/safe range/u);
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"n\":1e16}"))).toThrow(/safe/u);
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"n\":9007199254740991.5}"))).toThrow(/safe/u);
    expect(() => parseStrictJsonObject(Uint8Array.from([0x7b, 0x22, 0x73, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]))).toThrow();
    expect(() => parseStrictJsonObject(Uint8Array.from([0xef, 0xbb, 0xbf, ...textEncoder.encode("{\"a\":1}")]))).toThrow();
    expect(() => parseStrictJsonObject(Uint8Array.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0x01, 0x22, 0x7d]))).toThrow();
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"s\":\"\\udc00\"}"))).toThrow();
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"a\":1} true"))).toThrow();
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"n\":01}"))).toThrow();
    expect(parseStrictJsonObject(textEncoder.encode("{\"n\":9007199254740991}")).n).toBe(Number.MAX_SAFE_INTEGER);
    expect(parseStrictJsonObject(textEncoder.encode("{\"n\":1.5}")).n).toBe(1.5);
  });
});

describe("Hermes memory bridge private framing", () => {
  it("pulls a burst of small frames without a count bound", () => {
    const frames = Array.from({ length: 1_000 }, (_, index) => encodePrivateFrame(jsonBytes({ type: "ready", index })));
    const joined = Buffer.concat(frames);
    const decoder = new PrivateFrameDecoder();
    decoder.push(joined);

    let remaining = joined.byteLength;
    for (const frame of frames) {
      const result = decoder.next();
      expect(result.kind).toBe("frame");
      remaining -= frame.byteLength;
      expect(decoder.bufferedBytes()).toBe(remaining);
    }
    expect(decoder.next()).toEqual({ kind: "need_more" });
    expect(decoder.bufferedBytes()).toBe(0);
  });

  it("rejects over-cap private bodies in the decoder and encoder", () => {
    const bytes = Buffer.alloc(LENGTH_PREFIX_BYTES);
    bytes.writeUInt32BE(MAX_PRIVATE_FRAME_BYTES + 1, 0);
    const decoder = new PrivateFrameDecoder();
    decoder.push(bytes);
    const result = decoder.next();
    expect(result.kind).toBe("fatal");
    expect(decoder.bufferedBytes()).toBe(0);
    expect(() => encodePrivateFrame(Buffer.alloc(MAX_PRIVATE_FRAME_BYTES + 1, 0x20))).toThrow(/cap/u);
    expect(MAX_PRIVATE_FRAME_BYTES).toBe(87_859);
  });

  it("decodes a frame split at every byte boundary and keeps fatal state sticky", () => {
    const frame = encodePrivateFrame(jsonBytes({ type: "relay_shutdown" }));
    for (let split = 0; split <= frame.byteLength; split += 1) {
      const decoder = new PrivateFrameDecoder();
      decoder.push(frame.subarray(0, split));
      const first = decoder.next();
      if (split < frame.byteLength) {
        expect(first.kind, `split ${split}`).toBe("need_more");
        decoder.push(frame.subarray(split));
      }
      const decoded = split === frame.byteLength ? first : decoder.next();
      expect(decoded.kind, `split ${split}`).toBe("frame");
      if (decoded.kind === "frame") {
        expect(parseRelayToNode(decoded.body)).toMatchObject({ kind: "ok", frame: { kind: "relay_shutdown" } });
      }
    }

    const bad = Buffer.alloc(LENGTH_PREFIX_BYTES);
    bad.writeUInt32BE(MAX_PRIVATE_FRAME_BYTES + 1, 0);
    const decoder = new PrivateFrameDecoder();
    decoder.push(Buffer.concat([frame, bad]));
    expect(decoder.next().kind).toBe("frame");
    expect(decoder.next().kind).toBe("fatal");
    decoder.push(frame);
    expect(decoder.next().kind).toBe("fatal");
  });
});

describe("Hermes memory bridge relay-to-Node envelopes", () => {
  it("consumes every fixture vector through its owning wire assertion", () => {
    const consumed = assertFixtureVectors();
    expect(consumed).toBe(fixtureTotal());
    expect(new Set(allFixtureEntries().map((entry) => entry.name)).size).toBe(fixtureTotal());
  });

  it("walks every relay-to-Node fixture vector through the decoder and parser", () => {
    assertRelayToNodeFixtureVectors();
  });

  it("walks every public fixture vector through Node's public boundary", () => {
    assertPublicFixtureVectors();
  });

  it("records structurally valid relay-to-Node vectors whose action depends on bridge state", () => {
    expect(stateDependentNames()).toEqual([
      "relay frame envelope",
      "relay closed",
      "relay probe reply",
      "relay frame bytes",
      "relay closed bytes",
      "relay probe reply bytes",
      "relay closed then late probe reply",
      "relay probe reply after timeout",
      "relay probe reply never accepted connection",
    ]);
    for (const name of stateDependentNames()) {
      const vector = findFixtureVector(name);
      const frames = collectFrames(privateBytesForFixture(vector));
      expect(frames.every((frame) => frame !== "fatal"), name).toBe(true);
      for (const frame of frames) {
        if (frame !== "fatal") expect(parseRelayToNode(frame), name).toMatchObject({ kind: "ok" });
      }
    }
  });

  it("uses shared schemas for relay envelopes and public forwarded frames", () => {
    for (const envelope of [
      { type: "accepted", connection_id: "c1", extra: true },
      { type: "frame", connection_id: "c1", frame_b64: "eyJ0eXBlIjoicGluZyJ9", extra: true },
      { type: "closed", connection_id: "c1", extra: true },
      { type: "probe_reply", connection_id: "c1", nonce: "0123456789abcdef0123456789abcdef", extra: true },
      { type: "relay_shutdown", extra: true },
    ]) {
      expect(parseRelayToNode(jsonBytes(envelope)).kind, JSON.stringify(envelope)).toBe("fatal");
    }
    expect(parseRelayToNode(jsonBytes({
      type: "frame",
      connection_id: "c1",
      frame_b64: Buffer.alloc(MAX_PUBLIC_FRAME_BYTES + 1, 0x20).toString("base64"),
    })).kind).toBe("fatal");

    for (const publicFrame of [
      { type: "hello", request_id: "m", protocol_version: "v", client_name: "c", extra: true },
      { type: "tools_list", request_id: "m", extra: true },
      { type: "tools_call", request_id: "m", name: "memory_get", arguments: { passage_id: "p" }, extra: true },
      { type: "cancel", mcp_request_id: "m", extra: true },
      { type: "shutdown", extra: true },
    ]) {
      expect(parsePublicFrame(jsonBytes(publicFrame)).kind, JSON.stringify(publicFrame)).toBe("public_rejection");
    }
    expect(parsePublicFrame(Buffer.alloc(MAX_PUBLIC_FRAME_BYTES + 1, 0x20))).toMatchObject({
      kind: "public_rejection",
      reason: "public frame exceeds cap",
    });
  });

  it("returns typed outcomes when frame types share Object prototype names", () => {
    const prototypeNames = Object.getOwnPropertyNames(Object.prototype);
    for (const type of prototypeNames) {
      expect(() => parseRelayToNode(jsonBytes({ type, connection_id: "c1" })), `relay ${type}`).not.toThrow();
      expect(parseRelayToNode(jsonBytes({ type, connection_id: "c1" })), `relay ${type}`).toMatchObject({
        kind: "fatal",
        reason: "unknown relay frame type",
      });

      const publicBytes = jsonBytes({ type, request_id: "mcp-1" });
      expect(() => parsePublicFrame(publicBytes), `public ${type}`).not.toThrow();
      expect(parsePublicFrame(publicBytes), `public ${type}`).toMatchObject({
        kind: "public_rejection",
        disposition: "close",
        frameType: type,
        reason: "public frame type is not forwarded to Node",
      });

      const viaRelay = parseRelayToNode(jsonBytes({
        type: "frame",
        connection_id: "c1",
        frame_b64: Buffer.from(publicBytes).toString("base64"),
      }));
      expect(viaRelay, `relay frame ${type}`).toMatchObject({
        kind: "ok",
        frame: {
          kind: "frame",
          publicFrame: {
            kind: "public_rejection",
            disposition: "close",
            frameType: type,
            reason: "public frame type is not forwarded to Node",
          },
        },
      });
    }
  });

  it("reports the request id and disposition for rejected public call frames", () => {
    const rejected = parsePublicFrame(jsonBytes({
      type: "tools_call",
      request_id: "mcp-9",
      name: "memory_get",
      arguments: { passage_id: "p", extra: 1 },
    }));
    expect(rejected).toMatchObject({
      kind: "public_rejection",
      disposition: "deny",
      frameType: "tools_call",
      requestId: "mcp-9",
    });
    expect(parsePublicFrame(jsonBytes({ type: "shutdown", extra: true }))).toMatchObject({
      kind: "public_rejection",
      disposition: "silent",
      frameType: "shutdown",
    });
    expect(parsePublicFrame(jsonBytes({ type: "unknown" }))).toMatchObject({
      kind: "public_rejection",
      disposition: "close",
      frameType: "unknown",
    });
    expect(parsePublicFrame(jsonBytes({ type: "tools_list", request_id: "bad id" }))).toMatchObject({
      kind: "public_rejection",
      disposition: "close",
      frameType: "tools_list",
    });
  });

  it("pins request id, nonce, connection id, base64, and tool argument constraints", () => {
    expect(parsePublicFrame(jsonBytes({ type: "tools_list", request_id: "r".repeat(128) })).kind).toBe("ok");
    for (const id of ["r".repeat(129), "", "a\n", "a b", "é", "a\u0000"]) {
      expect(parsePublicFrame(jsonBytes({ type: "tools_list", request_id: id })).kind, JSON.stringify(id)).toBe("public_rejection");
    }
    expect(parsePublicFrame(jsonBytes({
      type: "hello",
      request_id: "bad id",
      protocol_version: "2026-10-12",
      client_name: "hermes",
    })).kind).toBe("public_rejection");
    expect(parsePublicFrame(jsonBytes({ type: "cancel", mcp_request_id: "bad id" })).kind).toBe("public_rejection");
    for (const nonce of ["0123456789ABCDEF0123456789abcdef", "0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdef0"]) {
      expect(parseRelayToNode(jsonBytes({ type: "probe_reply", connection_id: "c1", nonce })).kind, nonce).toBe("fatal");
    }
    for (const id of ["c18446744073709551616", "c0"]) {
      expect(parseRelayToNode(jsonBytes({ type: "accepted", connection_id: id })).kind, id).toBe("fatal");
    }
    expect(parseRelayToNode(jsonBytes({ type: "accepted", connection_id: "c18446744073709551615" })).kind).toBe("ok");
    expect(parseRelayToNode(jsonBytes({ type: "accepted", connection_id: "c01" })).kind).toBe("ok");
    expect(decodeStandardBase64("eyJ0eXBlIjoicGluZyJ9")).not.toBeNull();
    expect(decodeStandardBase64("eyJ0eXBlIjoicGluZyJ9fQ=")).toBeNull();
    expect(decodeStandardBase64("YQ==")).not.toBeNull();
    expect(decodeStandardBase64("YR==")).toBeNull();
    expect(decodeStandardBase64("YQ=")).toBeNull();
    expect(decodeStandardBase64("Y Q==")).toBeNull();
    expect(decodeStandardBase64("YQ-_")).toBeNull();

    const call = (args: Record<string, unknown>) => parsePublicFrame(jsonBytes({
      type: "tools_call",
      request_id: "m",
      name: "memory_search",
      arguments: args,
    })).kind;
    expect(call({ query: "a", limit: 1 })).toBe("ok");
    expect(call({ query: "a", limit: 20 })).toBe("ok");
    expect(call({ text: "a" })).toBe("ok");
    expect(call({ text: "a", query: "b" })).toBe("public_rejection");
    expect(call({ tag: "t" })).toBe("public_rejection");
    expect(call({ query: "a", limit: 0 })).toBe("public_rejection");
    expect(call({ query: "a", limit: 21 })).toBe("public_rejection");
    expect(call({ query: "a", limit: 1.5 })).toBe("public_rejection");
    expect(call({ query: "a", limit: "5" })).toBe("public_rejection");
    expect(call({ query: "a", extra: 1 })).toBe("public_rejection");
    expect(parsePublicFrame(jsonBytes({
      type: "tools_call",
      request_id: "m",
      name: "memory_insert",
      arguments: { text: "t", taint: "user_content", extra: 1 },
    })).kind).toBe("public_rejection");
    expect(parsePublicFrame(jsonBytes({
      type: "tools_call",
      request_id: "m",
      name: "memory_insert",
      arguments: { text: "t", taint: "other" },
    })).kind).toBe("public_rejection");
    expect(parsePublicFrame(jsonBytes({
      type: "tools_call",
      request_id: "m",
      name: "memory_insert",
      arguments: { text: "t", taint: "user_content", tags: [1] },
    })).kind).toBe("public_rejection");
    expect(parsePublicFrame(jsonBytes({
      type: "tools_call",
      request_id: "m",
      name: "memory_insert",
      arguments: { text: "t", taint: "user_content", tags: ["a"], passage_id: "p" },
    })).kind).toBe("ok");
    expect(parsePublicFrame(jsonBytes({
      type: "tools_call",
      request_id: "m",
      name: "memory_get",
      arguments: { passage_id: "p", extra: 1 },
    })).kind).toBe("public_rejection");
    expect(parsePublicFrame(jsonBytes({
      type: "tools_call",
      request_id: "m",
      name: "memory_get",
      arguments: [],
    })).kind).toBe("public_rejection");
    expect(parsePublicFrame(jsonBytes({
      type: "hello",
      request_id: "h",
      protocol_version: 1,
      client_name: "c",
    })).kind).toBe("public_rejection");
  });
});

describe("Hermes memory bridge Node-to-relay encoder", () => {
  it("reproduces every forwarding Node-to-relay fixture target from decoded input", () => {
    for (const vector of nodeToRelayVectors().filter((entry) =>
      entry.expected_action === "accept" || entry.expected_action === "decode_response_and_forward"
    )) {
      expectValidNodeToRelay(vector);
    }
  });

  it("turns invalid public response bytes into the fixed denial", () => {
    expect(HERMES_MEMORY_DENIAL).toBe("Memory request denied.");
    for (const vectorName of [
      "node result over cap",
      "node result mismatched id",
      "node result lone surrogate",
      "node result over depth",
      "node response private cap exact",
    ]) {
      const requestId = vectorName === "node response private cap exact" ? "mcp-100" : "mcp-1";
      expectDenialFromResponseBytes(requestId, innerResultBytes(vectorName));
    }
    for (const bytes of [
      textEncoder.encode("{\"type\":\"result\",\"request_id\":\"mcp-1\"}"),
      textEncoder.encode("{\"type\":\"result\",\"request_id\":\"mcp-1\",\"payload\":5}"),
      textEncoder.encode("{\"type\":\"result\",\"request_id\":\"mcp-1\",\"payload\":[]}"),
      textEncoder.encode("{\"type\":\"error\",\"request_id\":\"mcp-1\",\"payload\":{}}"),
      textEncoder.encode("{\"type\":\"error\",\"request_id\":\"mcp-1\",\"message\":{\"x\":1}}"),
      textEncoder.encode("{\"type\":\"result\",\"request_id\":\"mcp-1\",\"payload\":{},\"message\":\"m\"}"),
      textEncoder.encode("{\"type\":\"other\",\"request_id\":\"mcp-1\",\"payload\":{}}"),
      Uint8Array.from([0xef, 0xbb, 0xbf, ...textEncoder.encode("{\"type\":\"result\",\"request_id\":\"mcp-1\",\"payload\":{}}")]),
    ]) {
      expectDenialFromResponseBytes("mcp-1", bytes);
    }

    const prefix = "{\"type\":\"result\",\"request_id\":\"mcp-1\",\"payload\":{\"text\":\"";
    const suffix = "\"}}";
    const wellFormedOverCap = textEncoder.encode(`${prefix}${"a".repeat(MAX_RESULT_FRAME_BYTES - prefix.length - suffix.length + 1)}${suffix}`);
    expect(wellFormedOverCap.byteLength).toBe(MAX_RESULT_FRAME_BYTES + 1);
    expectDenialFromResponseBytes("mcp-1", wellFormedOverCap);
  });

  it("cannot produce invalid Node-to-relay fixture shapes from typed input", () => {
    const invalidLabels = new Set(["fatal_relay_error", "decode_response_and_deny"]);
    for (const vector of nodeToRelayVectors().filter((entry) => invalidLabels.has(entry.expected_action))) {
      dispatchFixtureVector("stream_cases", vector, () => undefined);
    }

    expect(() => encodeNodeToRelay({ type: "close", connectionId: "bad" })).toThrow(
      expect.objectContaining({ name: "HermesWireEncodeError", code: "invalid_connection_id" }),
    );
    expect(() => encodeNodeToRelay({ type: "probe", connectionId: "c1", nonce: "0123456789ABCDEF0123456789ABCDEF" })).toThrow(
      expect.objectContaining({ name: "HermesWireEncodeError", code: "invalid_nonce" }),
    );
    expect(() => encodeNodeToRelay({
      type: "response",
      connectionId: "c1",
      requestId: "x".repeat(129),
      publicPayloadBytes: publicErrorBytes("mcp-1"),
    })).toThrow(expect.objectContaining({ name: "HermesWireEncodeError", code: "invalid_request_id" }));
    expect(() => encodePrivateFrame(Buffer.alloc(MAX_PRIVATE_FRAME_BYTES + 1, 0x61))).toThrow(/cap/u);

    const paddedFromTypedInput = parsePayload(encodeNodeToRelay({
      type: "response",
      connectionId: "c1",
      requestId: "mcp-1",
      publicPayloadBytes: innerResultBytes("node result unpadded base64"),
    }));
    expect(paddedFromTypedInput.result_b64).toMatch(/=$/u);
  });

  it("uses padded base64 and keeps the longest private response within the seam cap", () => {
    const response = parsePayload(encodeNodeToRelay({
      type: "response",
      connectionId: "c1",
      requestId: "mcp-1",
      publicPayloadBytes: publicResultBytes("mcp-1", { x: "a" }),
    }));
    expect(response.result_b64).toBe("eyJ0eXBlIjoicmVzdWx0IiwicmVxdWVzdF9pZCI6Im1jcC0xIiwicGF5bG9hZCI6eyJ4IjoiYSJ9fQ==");

    const longestConnectionId = "c18446744073709551615";
    const longestRequestId = "r".repeat(128);
    const prefix = `{"type":"result","request_id":"${longestRequestId}","payload":{"text":"`;
    const suffix = "\"}}";
    const publicPayloadBytes = textEncoder.encode(`${prefix}${"a".repeat(MAX_RESULT_FRAME_BYTES - prefix.length - suffix.length)}${suffix}`);
    expect(publicPayloadBytes.byteLength).toBe(MAX_RESULT_FRAME_BYTES);
    const encoded = encodeNodeToRelay({
      type: "response",
      connectionId: longestConnectionId,
      requestId: longestRequestId,
      publicPayloadBytes,
    });
    expect(encoded.subarray(LENGTH_PREFIX_BYTES).byteLength).toBeLessThanOrEqual(MAX_PRIVATE_FRAME_BYTES);
  });
});
