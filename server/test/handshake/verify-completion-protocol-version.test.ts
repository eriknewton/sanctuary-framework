/**
 * Regression test for full-sweep #51:
 * verifyCompletion() must reject unsupported protocol_version values.
 *
 * Fails on 1d9fb29 (no version check); passes after fix.
 */

import { describe, it, expect } from "vitest";
import { verifyCompletion } from "../../src/handshake/protocol.js";
import type { HandshakeCompletion, HandshakeSession } from "../../src/handshake/types.js";

describe("verifyCompletion protocol_version check (#51)", () => {
  it("returns verified:false with version-mismatch error for unsupported protocol_version", () => {
    // Forge a completion with a future protocol version
    const completion = {
      protocol_version: "2.0",
      responder_nonce_signature: "dGVzdA",
      completed_at: new Date().toISOString(),
    } as unknown as HandshakeCompletion;

    const session: HandshakeSession = {
      session_id: "test-session",
      role: "responder",
      state: "responded",
      our_nonce: "dGVzdC1ub25jZQ",
      initiated_at: new Date().toISOString(),
      our_shr: {} as any,
    };

    const result = verifyCompletion(completion, session);

    expect(result.verified).toBe(false);
    expect(result.errors).toContain("Unsupported protocol version: 2.0");
    expect(result.sovereignty_level).toBe("unverified");
    expect(result.trust_tier).toBe("unverified");
  });
});
