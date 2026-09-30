/**
 * Tests for the credential-surrogacy bound table: every constant that the
 * design DERIVES from a shipped constant is pinned equal to its source here.
 *
 * WHY A TEST AND NOT AN IMPORT. `credential-surrogate/constants.ts` is loaded by
 * the root helper daemon, by root arming and by the broker, so it holds literals
 * rather than an import chain that would pull the audit log and a socket client
 * into all three. This file is the other half of that decision: it imports both
 * sides and fails if either moves, so the derivation cannot rot unnoticed.
 */

import { describe, expect, it } from "vitest";

import {
  MAX_SURROGATE_BINDINGS_PER_AGENT,
  MAX_SURROGATE_BINDINGS_PER_HOST,
  MAX_SURROGATE_DESTINATIONS_PER_BINDING,
  MAX_SURROGATE_ECHO_SCAN_BYTES,
  MAX_SURROGATE_UNLOCK_SECONDS,
  MAX_SURROGATE_VALUE_BYTES,
  SURROGATE_HELPER_MAX_CONCURRENT_QUERIES,
  SURROGATE_QUERY_TIMEOUT_MS,
  SURROGATE_WIRE_ENVELOPE_BYTES,
  SURROGATE_WIRE_MAX_FRAME_BYTES,
} from "../../src/credential-surrogate/constants.js";
import {
  MAX_LIVE_TOKENS_GLOBAL,
  MAX_LIVE_TOKENS_PER_CALLER,
} from "../../src/disclosure/broker/token-issuer.js";
import { PEER_RESOLVER_MAX_FRAME_BYTES } from "../../src/egress-gate/peer-resolver-protocol.js";
import { PEER_RESOLVER_MAX_CONCURRENT_LOOKUPS } from "../../src/egress-gate/peer-resolver-daemon.js";
import { PRIVILEGED_PEER_RUNNER_TIMEOUT_MS } from "../../src/egress-gate/peer-resolver-client.js";

describe("surrogate bounds are pinned to the constants they were derived from", () => {
  it("per-agent binding cap equals the per-caller live-token cap", () => {
    expect(MAX_SURROGATE_BINDINGS_PER_AGENT).toBe(MAX_LIVE_TOKENS_PER_CALLER);
  });

  it("per-host binding cap equals the global live-token cap", () => {
    expect(MAX_SURROGATE_BINDINGS_PER_HOST).toBe(MAX_LIVE_TOKENS_GLOBAL);
  });

  it("wire envelope budget equals the peer-resolver frame bound", () => {
    expect(SURROGATE_WIRE_ENVELOPE_BYTES).toBe(PEER_RESOLVER_MAX_FRAME_BYTES);
  });

  it("helper query concurrency equals the peer-resolver lookup cap", () => {
    expect(SURROGATE_HELPER_MAX_CONCURRENT_QUERIES).toBe(PEER_RESOLVER_MAX_CONCURRENT_LOOKUPS);
  });

  it("query deadline equals the privileged peer runner timeout", () => {
    expect(SURROGATE_QUERY_TIMEOUT_MS).toBe(PRIVILEGED_PEER_RUNNER_TIMEOUT_MS);
  });
});

describe("surrogate bounds that are derived arithmetically", () => {
  it("frame cap carries one fully escaped value plus the envelope", () => {
    expect(SURROGATE_WIRE_MAX_FRAME_BYTES).toBe(
      2 * MAX_SURROGATE_VALUE_BYTES + SURROGATE_WIRE_ENVELOPE_BYTES,
    );
  });

  it("echo scan ceiling is 256 times the longest value", () => {
    expect(MAX_SURROGATE_ECHO_SCAN_BYTES).toBe(256 * MAX_SURROGATE_VALUE_BYTES);
  });

  it("a value at the cap still fits one frame after worst-case JSON escaping", () => {
    // Worst case: every byte of the value needs a two-byte escape. JSON escapes
    // only `"`, `\` and tab that way, so a value of all quotes is the bound.
    const worst = '"'.repeat(MAX_SURROGATE_VALUE_BYTES);
    const encoded = Buffer.byteLength(
      `${JSON.stringify({ v: 1, id: "0".repeat(32), kind: "unlock", generation_id: 1, ttl_seconds: 1, secret: "s", value: worst })}\n`,
      "utf8",
    );
    expect(encoded).toBeLessThanOrEqual(SURROGATE_WIRE_MAX_FRAME_BYTES);
  });
});

describe("surrogate bounds that are stated outright", () => {
  it("holds the values the design table states", () => {
    expect(MAX_SURROGATE_DESTINATIONS_PER_BINDING).toBe(4);
    expect(MAX_SURROGATE_VALUE_BYTES).toBe(4096);
    expect(MAX_SURROGATE_UNLOCK_SECONDS).toBe(86400);
  });

  it("clamps an unlock to at most one day", () => {
    expect(MAX_SURROGATE_UNLOCK_SECONDS).toBe(24 * 60 * 60);
  });
});
