/**
 * Phase S1 — Supervisor wire protocol: framing, MAC auth, bounds, shape.
 *
 * These tests attack the socket's authentication and bounding directly (the
 * codex adversarial lens for split-process socket auth): a wrong secret must
 * not authenticate, an over-long length prefix must be rejected before
 * allocation, a corrupt frame must not parse, and a malformed shape must be
 * dropped post-MAC.
 */

import { describe, expect, it } from "vitest";
import {
  encodeFrame,
  FrameDecoder,
  mintAuthSecret,
  parseRequest,
  MAX_FRAME_BYTES,
  FRAME_HEADER_BYTES,
  type SupervisorRequest,
} from "../../src/supervisor/protocol.js";

const REQ: SupervisorRequest = {
  kind: "protect",
  agent_id: "a1",
  harness: "claude_code",
  config_path: "/conf/a.json",
  transient_key_b64: "AAAA",
};

describe("supervisor protocol framing", () => {
  it("round-trips a frame under the matching secret", () => {
    const secret = mintAuthSecret();
    const frame = encodeFrame(secret, REQ);
    const decoder = new FrameDecoder(secret);
    const out = decoder.push(frame);
    expect(out.status).toBe("frame");
    if (out.status === "frame") expect(out.message).toEqual(REQ);
  });

  it("rejects a frame MAC'd with a DIFFERENT secret (auth failure)", () => {
    const frame = encodeFrame(mintAuthSecret(), REQ);
    const decoder = new FrameDecoder(mintAuthSecret()); // wrong secret
    const out = decoder.push(frame);
    expect(out.status).toBe("error");
    if (out.status === "error") expect(out.reason).toBe("mac_failed");
  });

  it("rejects a frame whose payload was tampered after MAC (integrity)", () => {
    const secret = mintAuthSecret();
    const frame = Buffer.from(encodeFrame(secret, REQ));
    // Flip a byte in the payload region (past the 4-byte len + 32-byte MAC).
    frame[FRAME_HEADER_BYTES + 1] ^= 0xff;
    const out = new FrameDecoder(secret).push(frame);
    expect(out.status).toBe("error");
    if (out.status === "error") expect(out.reason).toBe("mac_failed");
  });

  it("rejects an over-long length prefix BEFORE buffering it (bound)", () => {
    const secret = mintAuthSecret();
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
    const out = new FrameDecoder(secret).push(buf);
    expect(out.status).toBe("error");
    if (out.status === "error") expect(out.reason).toBe("too_large");
  });

  it("waits for more bytes on a partial frame (incomplete)", () => {
    const secret = mintAuthSecret();
    const frame = encodeFrame(secret, REQ);
    const decoder = new FrameDecoder(secret);
    const half = decoder.push(frame.subarray(0, 8));
    expect(half.status).toBe("incomplete");
    const rest = decoder.push(frame.subarray(8));
    expect(rest.status).toBe("frame");
  });

  it("reassembles a frame fed one byte at a time", () => {
    const secret = mintAuthSecret();
    const frame = encodeFrame(secret, REQ);
    const decoder = new FrameDecoder(secret);
    let final: ReturnType<FrameDecoder["push"]> = { status: "incomplete" };
    for (let i = 0; i < frame.length; i++) {
      final = decoder.push(frame.subarray(i, i + 1));
    }
    expect(final.status).toBe("frame");
  });

  it("refuses to encode an over-MAX message", () => {
    const secret = mintAuthSecret();
    const big: SupervisorRequest = { ...REQ, transient_key_b64: "x".repeat(MAX_FRAME_BYTES + 1) };
    expect(() => encodeFrame(secret, big)).toThrow(/MAX_FRAME_BYTES/);
  });
});

describe("supervisor protocol shape validation", () => {
  it("accepts a well-formed protect", () => {
    expect(parseRequest(REQ)).toEqual(REQ);
  });

  it("rejects an unknown harness", () => {
    expect(parseRequest({ ...REQ, harness: "not-a-harness" })).toBeNull();
  });

  it("rejects a protect missing the transient key", () => {
    const { transient_key_b64: _omit, ...rest } = REQ;
    void _omit;
    expect(parseRequest(rest)).toBeNull();
  });

  it("rejects an empty agent_id", () => {
    expect(parseRequest({ ...REQ, agent_id: "" })).toBeNull();
  });

  it("rejects an unknown kind", () => {
    expect(parseRequest({ kind: "exec", agent_id: "a" })).toBeNull();
  });

  it("accepts unprotect and status", () => {
    expect(parseRequest({ kind: "unprotect", agent_id: "a" })).toEqual({
      kind: "unprotect",
      agent_id: "a",
    });
    expect(parseRequest({ kind: "status" })).toEqual({ kind: "status", agent_id: undefined });
  });
});
