/**
 * Regression test for full-sweep #69:
 * generateNonce() must throw if randomBytes returns unexpected length.
 *
 * Fails on 1d9fb29 (no length assertion); passes after fix.
 */

import { describe, it, expect, vi } from "vitest";

describe("generateNonce entropy assertion (#69)", () => {
  it("throws when randomBytes returns a short buffer", async () => {
    // Mock the random module to return a short buffer
    vi.doMock("../../src/core/random.js", () => ({
      randomBytes: () => new Uint8Array(16), // 16 bytes instead of 32
    }));

    // Re-import protocol after mock is installed
    const { initiateHandshake } = await import("../../src/handshake/protocol.js");

    // initiateHandshake calls generateNonce internally
    expect(() => initiateHandshake({} as any)).toThrow(
      "Nonce generation failed: randomBytes returned unexpected length"
    );

    vi.doUnmock("../../src/core/random.js");
  });
});
