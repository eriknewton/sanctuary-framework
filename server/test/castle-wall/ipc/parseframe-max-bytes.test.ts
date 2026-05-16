/**
 * parseFrame MAX_FRAME_BYTES cap tests.
 *
 * Verifies that oversize frame declarations are rejected before buffer
 * allocation, preventing resource-exhaustion DoS via malformed headers.
 */

import { describe, it, expect, vi, afterEach } from "vitest";

// Helper: build a raw frame header declaring a specific content-length
function headerForLength(n: number): Uint8Array {
  return new TextEncoder().encode(`Content-Length: ${n}\r\n\r\n`);
}

describe("castle-wall/ipc/framing : MAX_FRAME_BYTES cap", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("parses a frame with declared length just under the default cap", async () => {
    const { parseFrame, MAX_FRAME_BYTES } = await import(
      "../../../src/castle-wall/ipc/framing.js"
    );
    const declaredLength = MAX_FRAME_BYTES - 1;
    // Only provide the header + enough for "need_more" (we just verify no throw)
    const header = headerForLength(declaredLength);
    // With insufficient body bytes, should return need_more (not throw)
    const step = parseFrame(header);
    expect(step.kind).toBe("need_more");
  });

  it("rejects a frame with declared length exceeding the default cap", async () => {
    const { parseFrame, MAX_FRAME_BYTES } = await import(
      "../../../src/castle-wall/ipc/framing.js"
    );
    const declaredLength = MAX_FRAME_BYTES + 1;
    const header = headerForLength(declaredLength);
    // Append a single body byte so the header is complete
    const buf = new Uint8Array(header.length + 1);
    buf.set(header, 0);
    const step = parseFrame(buf);
    expect(step.kind).toBe("error");
    if (step.kind === "error") {
      expect(step.reason).toMatch(/frame exceeds max bytes/);
      expect(step.oversize).toEqual({ declaredLength, maxAllowed: MAX_FRAME_BYTES });
    }
  });

  it("rejects a frame with declared length of 2^32 (boundary)", async () => {
    const { parseFrame, MAX_FRAME_BYTES } = await import(
      "../../../src/castle-wall/ipc/framing.js"
    );
    const declaredLength = 2 ** 32;
    const header = headerForLength(declaredLength);
    const buf = new Uint8Array(header.length + 1);
    buf.set(header, 0);
    const step = parseFrame(buf);
    expect(step.kind).toBe("error");
    if (step.kind === "error") {
      expect(step.reason).toMatch(/frame exceeds max bytes/);
      expect(step.oversize).toEqual({ declaredLength, maxAllowed: MAX_FRAME_BYTES });
    }
  });

  it("respects env override SANCTUARY_MAX_FRAME_BYTES=2048", async () => {
    vi.stubEnv("SANCTUARY_MAX_FRAME_BYTES", "2048");
    const { parseFrame, MAX_FRAME_BYTES } = await import(
      "../../../src/castle-wall/ipc/framing.js"
    );
    expect(MAX_FRAME_BYTES).toBe(2048);
    // 2049 should return error with oversize metadata
    const header = headerForLength(2049);
    const buf = new Uint8Array(header.length + 1);
    buf.set(header, 0);
    const step = parseFrame(buf);
    expect(step.kind).toBe("error");
    if (step.kind === "error") {
      expect(step.reason).toMatch(/frame exceeds max bytes/);
      expect(step.oversize).toEqual({ declaredLength: 2049, maxAllowed: 2048 });
    }
    // 2047 should not error (returns need_more)
    const okHeader = headerForLength(2047);
    expect(parseFrame(okHeader).kind).toBe("need_more");
  });

  it("fails closed when env override is below minimum (100)", async () => {
    vi.stubEnv("SANCTUARY_MAX_FRAME_BYTES", "100");
    await expect(
      import("../../../src/castle-wall/ipc/framing.js")
    ).rejects.toThrow(/SANCTUARY_MAX_FRAME_BYTES must be an integer between/);
  });
});
