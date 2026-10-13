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
import { HERMES_MEMORY_WIRE_STATE_RECORDED_FOR_2A_II } from "./fixture-state-vectors.js";

type FixtureEntry = {
  readonly name: string;
  readonly direction?: string;
  readonly channel?: string;
  readonly frame?: Record<string, unknown>;
  readonly expected_action: string;
  readonly bytes_hex?: string;
};

const relayFixture = JSON.parse(
  readFileSync(new URL("./fixtures/relay-frames.json", import.meta.url), "utf8"),
) as {
  readonly valid: readonly FixtureEntry[];
  readonly malformed: readonly FixtureEntry[];
  readonly wrong_allowlist: readonly FixtureEntry[];
  readonly stream_cases: readonly FixtureEntry[];
};

const textEncoder = new TextEncoder();

function jsonBytes(value: Record<string, unknown>): Uint8Array {
  return textEncoder.encode(JSON.stringify(value));
}

function parsePayload(frame: Buffer): Record<string, unknown> {
  return JSON.parse(frame.subarray(LENGTH_PREFIX_BYTES).toString("utf8")) as Record<string, unknown>;
}

function framedJson(value: Record<string, unknown>): Buffer {
  return encodePrivateFrame(jsonBytes(value));
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

function publicResultBytes(requestId: string, payload: Record<string, unknown>): Uint8Array {
  return jsonBytes({ type: "result", request_id: requestId, payload });
}

function stateRecordedNames(): readonly string[] {
  return HERMES_MEMORY_WIRE_STATE_RECORDED_FOR_2A_II.map((entry) => entry.name);
}

describe("Hermes memory bridge strict JSON", () => {
  it("rejects duplicate keys at nested depth and after unescaping", () => {
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"outer\":{\"a\":1,\"a\":2}}"))).toThrow(/duplicate/u);
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"a\":1,\"\\u0061\":2}"))).toThrow(/duplicate/u);
  });

  it("keeps proto spelling as an own key on a null-prototype object", () => {
    const parsed = parseStrictJsonObject(textEncoder.encode("{\"arguments\":{\"__proto__\":{\"text\":\"not inherited\"}}}"));
    const args = parsed.arguments as Record<string, unknown>;
    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(Object.getPrototypeOf(args)).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(args, "__proto__")).toBe(true);
    expect(args.text).toBeUndefined();
  });

  it("accepts the seam depth and refuses one more nested public argument array", () => {
    const nested = (count: number): Uint8Array => textEncoder.encode(
      `{"type":"tools_call","request_id":"mcp-1","name":"memory_search","arguments":{"text":${"[".repeat(count)}"alpha"${"]".repeat(count)}}}`,
    );
    expect(parseStrictJsonObject(nested(MAX_JSON_NESTING_DEPTH - 1))).toMatchObject({ type: "tools_call" });
    expect(() => parseStrictJsonObject(nested(MAX_JSON_NESTING_DEPTH))).toThrow(/nesting/u);
  });

  it("refuses numbers outside the safe integer range", () => {
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"n\":9007199254740992}"))).toThrow(/safe range/u);
    expect(() => parseStrictJsonObject(textEncoder.encode("{\"n\":-9007199254740992}"))).toThrow(/safe range/u);
  });
});

describe("Hermes memory bridge private framing", () => {
  it("pulls a burst of small frames without a count bound", () => {
    const frames = Array.from({ length: 1_000 }, (_, index) => framedJson({ type: "ready", index }));
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

  it("rejects an over-cap private length before a payload body", () => {
    const bytes = Buffer.alloc(LENGTH_PREFIX_BYTES);
    bytes.writeUInt32BE(MAX_PRIVATE_FRAME_BYTES + 1, 0);
    const decoder = new PrivateFrameDecoder();
    decoder.push(bytes);
    const result = decoder.next();
    expect(result.kind).toBe("fatal");
    expect(decoder.bufferedBytes()).toBe(0);
  });

  it("decodes one frame split at every byte boundary", () => {
    const frame = framedJson({ type: "relay_shutdown" });
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
  });
});

describe("Hermes memory bridge relay-to-Node envelopes", () => {
  it("asserts every relay-to-Node fixture vector that is structural in the wire layer", () => {
    const vectors = [
      ...relayFixture.valid.filter((entry) => entry.direction === "relayToNode"),
      ...relayFixture.wrong_allowlist.filter((entry) => entry.direction === "relayToNode"),
      ...relayFixture.stream_cases.filter((entry) => entry.channel === "relay_to_node"),
    ];
    expect(vectors.length).toBeGreaterThan(0);

    for (const vector of vectors) {
      const bytes = vector.bytes_hex === undefined
        ? framedJson(vector.frame ?? {})
        : Buffer.from(vector.bytes_hex, "hex");
      const frames = collectFrames(bytes);
      if (vector.name === "relay over cap length") {
        expect(frames, vector.name).toEqual(["fatal"]);
        continue;
      }
      expect(frames.length, vector.name).toBeGreaterThan(0);
      for (const frame of frames) {
        expect(frame, vector.name).not.toBe("fatal");
        if (frame === "fatal") continue;
        const parsed = parseRelayToNode(frame);
        if (vector.expected_action === "fatal_bridge" && !stateRecordedNames().includes(vector.name)) {
          expect(parsed.kind, vector.name).toBe("fatal");
        } else {
          expect(parsed.kind, vector.name).toBe("ok");
        }
      }
    }
  });

  it("records relay-to-Node fixture vectors that need bridge state in slice 2a-ii", () => {
    expect(stateRecordedNames()).toEqual([
      "relay closed then late probe reply",
      "relay probe reply after timeout",
      "relay probe reply never accepted connection",
    ]);
    for (const name of stateRecordedNames()) {
      const vector = relayFixture.stream_cases.find((entry) => entry.name === name);
      expect(vector, name).toBeDefined();
      const frames = collectFrames(Buffer.from(vector!.bytes_hex!, "hex"));
      expect(frames.every((frame) => frame !== "fatal"), name).toBe(true);
      for (const frame of frames) {
        if (frame !== "fatal") expect(parseRelayToNode(frame).kind, name).toBe("ok");
      }
    }
  });

  it("parses forwarded public frames and reports public rejections without rejecting the private envelope", () => {
    const accepted = parseRelayToNode(framedJson({
      type: "frame",
      connection_id: "c1",
      frame_b64: Buffer.from(JSON.stringify({
        type: "tools_call",
        request_id: "mcp-1",
        name: "memory_search",
        arguments: { query: "alpha", limit: 1 },
      })).toString("base64"),
    }).subarray(LENGTH_PREFIX_BYTES));
    expect(accepted).toMatchObject({ kind: "ok", frame: { kind: "frame", publicFrame: { kind: "ok" } } });

    const rejected = parseRelayToNode(framedJson({
      type: "frame",
      connection_id: "c1",
      frame_b64: Buffer.from("{\"type\":\"tools_call\",\"request_id\":\"mcp-1\",\"name\":\"memory_search\",\"arguments\":{\"text\":\"a\",\"text\":\"b\"}}").toString("base64"),
    }).subarray(LENGTH_PREFIX_BYTES));
    expect(rejected).toMatchObject({ kind: "ok", frame: { kind: "frame", publicFrame: { kind: "public_rejection" } } });

    expect(parsePublicFrame(jsonBytes({ type: "ping" }))).toMatchObject({ kind: "public_rejection" });
  });

  it("rejects extra keys on relay shutdown", () => {
    expect(parseRelayToNode(jsonBytes({ type: "relay_shutdown", extra: true }))).toMatchObject({ kind: "fatal" });
  });
});

describe("Hermes memory bridge Node-to-relay encoder", () => {
  it("reproduces valid Node-to-relay fixture targets from typed input", () => {
    const cases = [
      {
        name: "node ready",
        encoded: encodeNodeToRelay({ type: "ready" }),
      },
      {
        name: "node probe",
        encoded: encodeNodeToRelay({
          type: "probe",
          connectionId: "c1",
          nonce: "0123456789abcdef0123456789abcdef",
        }),
      },
      {
        name: "node response",
        encoded: encodeNodeToRelay({
          type: "response",
          connectionId: "c1",
          requestId: "mcp-1",
          publicPayloadBytes: publicResultBytes("mcp-1", { content: [] }),
        }),
      },
      {
        name: "node close",
        encoded: encodeNodeToRelay({ type: "close", connectionId: "c1" }),
      },
      {
        name: "node result valid",
        encoded: encodeNodeToRelay({
          type: "response",
          connectionId: "c1",
          requestId: "mcp-1",
          publicPayloadBytes: publicResultBytes("mcp-1", {}),
        }),
      },
      {
        name: "node result padded base64",
        encoded: encodeNodeToRelay({
          type: "response",
          connectionId: "c1",
          requestId: "mcp-1",
          publicPayloadBytes: publicResultBytes("mcp-1", { x: "a" }),
        }),
      },
      {
        name: "node close then late response",
        encoded: encodeNodeToRelay({ type: "close", connectionId: "c2" }),
      },
    ];

    for (const testCase of cases) {
      const fixture = [
        ...relayFixture.valid.filter((entry) => entry.direction === "nodeToRelay"),
        ...relayFixture.stream_cases.filter((entry) => entry.channel === "node_to_relay"),
      ].find((entry) => entry.name === testCase.name);
      expect(fixture, testCase.name).toBeDefined();
      const expected = fixture!.bytes_hex === undefined
        ? fixture!.frame
        : JSON.parse(Buffer.from(fixture!.bytes_hex!, "hex").subarray(LENGTH_PREFIX_BYTES).toString("utf8"));
      expect(parsePayload(testCase.encoded), testCase.name).toEqual(expected);
    }
  });

  it("uses padded base64 and emits the fixed denial for result bytes outside the public result contract", () => {
    const response = parsePayload(encodeNodeToRelay({
      type: "response",
      connectionId: "c1",
      requestId: "mcp-1",
      publicPayloadBytes: publicResultBytes("mcp-1", { x: "a" }),
    }));
    expect(response.result_b64).toBe("eyJ0eXBlIjoicmVzdWx0IiwicmVxdWVzdF9pZCI6Im1jcC0xIiwicGF5bG9hZCI6eyJ4IjoiYSJ9fQ==");

    const overCap = parsePayload(encodeNodeToRelay({
      type: "response",
      connectionId: "c1",
      requestId: "mcp-1",
      publicPayloadBytes: Buffer.alloc(MAX_RESULT_FRAME_BYTES + 1, 0x61),
    }));
    const denial = Buffer.from(overCap.result_b64 as string, "base64").toString("utf8");
    expect(JSON.parse(denial)).toEqual({
      type: "error",
      request_id: "mcp-1",
      message: HERMES_MEMORY_DENIAL,
    });
  });

  it("refuses ids and nonces outside the relay field contract", () => {
    expect(() => encodeNodeToRelay({ type: "close", connectionId: "c0" })).toThrow(/connection/u);
    expect(() => encodeNodeToRelay({ type: "probe", connectionId: "c1", nonce: "0123456789ABCDEF0123456789ABCDEF" })).toThrow(/nonce/u);
    expect(() => encodeNodeToRelay({
      type: "response",
      connectionId: "c1",
      requestId: "x".repeat(129),
      publicPayloadBytes: buildDeniedPublicResponseBytes("mcp-1"),
    })).toThrow(/request/u);
  });

  it("rejects unpadded standard base64 where padding is required", () => {
    expect(decodeStandardBase64("eyJ4IjoiYSJ9")).not.toBeNull();
    expect(decodeStandardBase64("eyJ4IjoiYSJ9fQ")).toBeNull();
  });

  it("keeps the longest private response within the seam cap", () => {
    const longestConnectionId = "c18446744073709551615";
    const longestRequestId = "r".repeat(128);
    const prefix = `{"type":"result","request_id":"${longestRequestId}","payload":{"text":"`;
    const suffix = "\"}}";
    const publicPayloadBytes = textEncoder.encode(`${prefix}${"a".repeat(MAX_PUBLIC_FRAME_BYTES - prefix.length - suffix.length)}${suffix}`);
    expect(publicPayloadBytes.byteLength).toBe(MAX_PUBLIC_FRAME_BYTES);
    const encoded = encodeNodeToRelay({
      type: "response",
      connectionId: longestConnectionId,
      requestId: longestRequestId,
      publicPayloadBytes,
    });
    expect(encoded.subarray(LENGTH_PREFIX_BYTES).byteLength).toBeLessThanOrEqual(MAX_PRIVATE_FRAME_BYTES);
  });
});
