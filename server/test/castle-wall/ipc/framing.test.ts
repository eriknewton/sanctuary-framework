/**
 * Castle Wall IPC framing tests.
 *
 * Pure encode/decode round-trips against the LSP-style Content-Length frame.
 * No transport. PR 2 wires this onto a real Unix domain socket.
 */

import { describe, it, expect } from "vitest";
import {
  frame,
  parseFrame,
  parseSingleFrame,
  MAX_FRAME_BYTES,
} from "../../../src/castle-wall/ipc/framing.js";
import { IpcFramingError } from "../../../src/castle-wall/errors.js";

describe("castle-wall/ipc/framing : encode + decode", () => {
  it("round-trips a small JSON body", () => {
    const body = JSON.stringify({ type: "status_request", request_id: "abc123" });
    const encoded = frame(body);
    expect(parseSingleFrame(encoded)).toBe(body);
  });

  it("emits a Content-Length header matching the byte length (UTF-8)", () => {
    const body = JSON.stringify({ msg: "hello é world" });
    const encoded = frame(body);
    const headerText = new TextDecoder().decode(encoded.subarray(0, encoded.indexOf(13)));
    expect(headerText.startsWith("Content-Length: ")).toBe(true);
    const advertised = Number(headerText.slice("Content-Length: ".length));
    const expected = new TextEncoder().encode(body).length;
    expect(advertised).toBe(expected);
  });

  it("returns need_more for an incomplete header", () => {
    const partial = new TextEncoder().encode("Content-Length: 5");
    expect(parseFrame(partial)).toEqual({ kind: "need_more" });
  });

  it("bounds header bytes without counting the body against the header limit", () => {
    const validHeader = `Content-Length: ${MAX_FRAME_BYTES}\r\n\r\n`;
    // One GiB is the largest supported frame-size setting, with ten decimal digits.
    const maxHeader = `Content-Length: ${1024 ** 3}\r\n\r\n`.length;
    const longestHeader = validHeader.replace(": ", `: ${"0".repeat(maxHeader - validHeader.length)}`);
    const encode = (text: string) => new TextEncoder().encode(text);
    expect(parseFrame(encode("x".repeat(longestHeader.length))).kind).toBe("error");
    expect(parseFrame(encode(`Content-Length: ${" ".repeat(longestHeader.length)}0\r\n\r\n`)).kind).toBe("error");
    expect(parseFrame(encode(longestHeader))).toEqual({ kind: "need_more" });
    expect(parseFrame(encode(longestHeader.slice(0, -1)))).toEqual({ kind: "need_more" });
    expect(parseSingleFrame(frame("x".repeat(longestHeader.length * 2)))).toBe("x".repeat(longestHeader.length * 2));
  });

  it("returns need_more when body bytes have not all arrived", () => {
    const body = JSON.stringify({ a: 1 });
    const encoded = frame(body);
    const truncated = encoded.subarray(0, encoded.length - 2);
    expect(parseFrame(truncated)).toEqual({ kind: "need_more" });
  });

  it("rejects malformed Content-Length values", () => {
    const bad = new TextEncoder().encode("Content-Length: -1\r\n\r\n{}");
    const step = parseFrame(bad);
    expect(step.kind).toBe("error");
  });

  it("rejects missing Content-Length header", () => {
    const bad = new TextEncoder().encode("X-Other: 1\r\n\r\n{}");
    const step = parseFrame(bad);
    expect(step.kind).toBe("error");
  });

  it("parseSingleFrame throws on extra bytes after the frame", () => {
    const body = "{}";
    const encoded = frame(body);
    const padded = new Uint8Array(encoded.length + 3);
    padded.set(encoded, 0);
    expect(() => parseSingleFrame(padded)).toThrow(IpcFramingError);
  });

  it("handles two concatenated frames by reporting consumed bytes", () => {
    const a = frame(JSON.stringify({ a: 1 }));
    const b = frame(JSON.stringify({ b: 2 }));
    const both = new Uint8Array(a.length + b.length);
    both.set(a, 0);
    both.set(b, a.length);
    const step = parseFrame(both);
    expect(step.kind).toBe("complete");
    if (step.kind === "complete") {
      expect(step.body).toBe(JSON.stringify({ a: 1 }));
      expect(step.consumedBytes).toBe(a.length);
    }
  });
});
