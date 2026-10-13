import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  HERMES_MEMORY_DENIAL,
  LENGTH_PREFIX_BYTES,
  MAX_JSON_NESTING_DEPTH,
  MAX_PRIVATE_FRAME_BYTES,
  MAX_PUBLIC_FRAME_BYTES,
  MAX_RESULT_FRAME_BYTES,
  PrivateFrameDecoder,
  buildDeniedPublicResponseBytes,
  decodeStandardBase64,
  encodeNodeToRelay,
  encodePrivateFrame,
  parsePublicFrame,
  parseRelayToNode,
  parseStrictJsonObject,
} from "../../src/hermes-memory-bridge/index.js";
import { HERMES_MEMORY_WIRE_STATE_DEPENDENT_VECTORS } from "./fixture-state-vectors.js";

type FixtureEntry = {
  readonly name: string;
  readonly direction?: string;
  readonly channel?: string;
  readonly frame?: Record<string, unknown>;
  readonly expected_action: string;
  readonly bytes_hex?: string;
};

const fixtureUrl = new URL("./fixtures/relay-frames.json", import.meta.url);
const relayFixtureText = readFileSync(fixtureUrl, "utf8");
const relayFixture = JSON.parse(relayFixtureText) as {
  readonly valid: readonly FixtureEntry[];
  readonly malformed: readonly FixtureEntry[];
  readonly wrong_allowlist: readonly FixtureEntry[];
  readonly stream_cases: readonly FixtureEntry[];
};

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

function publicResultBytes(requestId: string, payload: Record<string, unknown>): Uint8Array {
  return jsonBytes({ type: "result", request_id: requestId, payload });
}

function publicErrorBytes(requestId: string): Uint8Array {
  return jsonBytes({ type: "error", request_id: requestId, message: HERMES_MEMORY_DENIAL });
}

function decodedResponsePayload(frame: Buffer): Record<string, unknown> {
  const response = parsePayload(frame);
  return JSON.parse(Buffer.from(response.result_b64 as string, "base64").toString("utf8")) as Record<string, unknown>;
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
  return [
    ...relayFixture.valid,
    ...relayFixture.malformed,
    ...relayFixture.wrong_allowlist,
    ...relayFixture.stream_cases,
  ];
}

function relayToNodeVectors(): readonly FixtureEntry[] {
  return allFixtureEntries().filter((entry) => entry.direction === "relayToNode" || entry.channel === "relay_to_node");
}

function nodeToRelayVectors(): readonly FixtureEntry[] {
  return allFixtureEntries().filter((entry) => entry.direction === "nodeToRelay" || entry.channel === "node_to_relay");
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
      return { kind: "frame", connectionId: envelope.connection_id };
    default:
      throw new Error("not a typed relay-to-Node frame");
  }
}

function expectDenialFromResponseBytes(requestId: string, publicBytes: Uint8Array): void {
  expect(decodedResponsePayload(encodeNodeToRelay({
    type: "response",
    connectionId: "c1",
    requestId,
    publicPayloadBytes: publicBytes,
  }))).toEqual({
    type: "error",
    request_id: requestId,
    message: HERMES_MEMORY_DENIAL,
  });
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
  it("walks every relay-to-Node fixture vector through the decoder and parser", () => {
    const handled = new Set<string>();
    for (const vector of relayToNodeVectors()) {
      handled.add(vector.name);
      const frames = collectFrames(privateBytesForFixture(vector));
      if (vector.name === "relay over cap length") {
        expect(frames, vector.name).toEqual(["fatal"]);
        continue;
      }
      expect(frames.length, vector.name).toBeGreaterThan(0);
      for (const frame of frames) {
        expect(frame, vector.name).not.toBe("fatal");
        if (frame === "fatal") continue;
        const parsed = parseRelayToNode(frame);
        if (vector.expected_action === "fatal_bridge" && !isStateDependent(vector.name)) {
          expect(parsed.kind, vector.name).toBe("fatal");
        } else {
          expect(parsed.kind, vector.name).toBe("ok");
          if (parsed.kind === "ok") expect(parsed.frame, vector.name).toMatchObject(expectedRelayFrameFromBody(frame));
        }
      }
    }
    expect(handled.size).toBe(relayToNodeVectors().length);
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
      name: "memory_get",
      arguments: { passage_id: "p", extra: 1 },
    })).kind).toBe("public_rejection");
  });
});

describe("Hermes memory bridge Node-to-relay encoder", () => {
  it("reproduces every valid Node-to-relay fixture target from typed input", () => {
    const cases: Readonly<Record<string, Buffer>> = {
      "node ready": encodeNodeToRelay({ type: "ready" }),
      "node probe": encodeNodeToRelay({
        type: "probe",
        connectionId: "c1",
        nonce: "0123456789abcdef0123456789abcdef",
      }),
      "node response": encodeNodeToRelay({
        type: "response",
        connectionId: "c1",
        requestId: "mcp-1",
        publicPayloadBytes: publicResultBytes("mcp-1", { content: [] }),
      }),
      "node close": encodeNodeToRelay({ type: "close", connectionId: "c1" }),
      "node result valid": encodeNodeToRelay({
        type: "response",
        connectionId: "c1",
        requestId: "mcp-1",
        publicPayloadBytes: publicResultBytes("mcp-1", {}),
      }),
      "node result padded base64": encodeNodeToRelay({
        type: "response",
        connectionId: "c1",
        requestId: "mcp-1",
        publicPayloadBytes: publicResultBytes("mcp-1", { x: "a" }),
      }),
      "node close then late response": encodeNodeToRelay({ type: "close", connectionId: "c2" }),
    };

    const validNames = new Set(
      nodeToRelayVectors()
        .filter((entry) =>
          entry.expected_action === "accept" ||
          entry.expected_action === "decode_response_and_forward" ||
          entry.name === "node close then late response")
        .map((entry) => entry.name),
    );
    expect(new Set(Object.keys(cases))).toEqual(validNames);

    for (const [name, encoded] of Object.entries(cases)) {
      const vector = findFixtureVector(name);
      const expectedFrames = collectFrames(privateBytesForFixture(vector));
      const expectedBody = expectedFrames[0];
      expect(expectedBody, name).not.toBe("fatal");
      if (expectedBody !== undefined && expectedBody !== "fatal") {
        expect(parsePayload(encoded), name).toEqual(JSON.parse(Buffer.from(expectedBody).toString("utf8")));
      }
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
      textEncoder.encode("{\"type\":\"error\",\"request_id\":\"mcp-1\",\"payload\":{}}"),
      textEncoder.encode("{\"type\":\"error\",\"request_id\":\"mcp-1\",\"message\":{\"x\":1}}"),
      textEncoder.encode("{\"type\":\"result\",\"request_id\":\"mcp-1\",\"payload\":{},\"message\":\"m\"}"),
      textEncoder.encode("{\"type\":\"other\",\"request_id\":\"mcp-1\",\"payload\":{}}"),
      Uint8Array.from([0xef, 0xbb, 0xbf, ...textEncoder.encode("{\"type\":\"result\",\"request_id\":\"mcp-1\",\"payload\":{}}")]),
    ]) {
      expectDenialFromResponseBytes("mcp-1", bytes);
    }
  });

  it("cannot produce invalid Node-to-relay fixture shapes from typed input", () => {
    const invalidNames = new Set(
      nodeToRelayVectors()
        .filter((entry) =>
          entry.expected_action !== "accept" &&
          entry.expected_action !== "decode_response_and_forward" &&
          entry.name !== "node close then late response")
        .map((entry) => entry.name),
    );
    expect(invalidNames).toEqual(new Set([
      "unexpected field",
      "tools call on node side",
      "node result over cap",
      "node result mismatched id",
      "node result lone surrogate",
      "node result over depth",
      "node result unpadded base64",
      "node response private cap exact",
      "node response private cap over",
    ]));

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
