/**
 * Unit tests for the read-side re-verification helper (Slice R core).
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  reverifyEntryProducerSignature,
  reverifyBasisCounts,
} from "../../src/principal-policy/producer-reverify.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../src/castle-wall/constants.js";

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const priv = ed25519.utils.randomPrivateKey();
const pubB64 = toBase64url(ed25519.getPublicKey(priv));
const CANONICAL = JSON.stringify({ layer: "l1", operation: "egress_blocked" });
const TS = 1_750_000_000_000;
const SEQ = 7;

function signedDetails(): Record<string, unknown> {
  const sig = ed25519.sign(producerSigningBytes(CANONICAL, TS, SEQ), priv);
  return {
    seq: SEQ,
    [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
    [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: CANONICAL,
    [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: TS,
    [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  };
}

describe("reverifyEntryProducerSignature", () => {
  it("verifies a genuine signed entry against the pinned key", () => {
    expect(reverifyEntryProducerSignature(signedDetails(), pubB64)).toBe(
      "producer_signed_verified",
    );
  });

  it("rejects a producer_signed entry with a missing signature (key present)", () => {
    const d = signedDetails();
    delete d[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY];
    expect(reverifyEntryProducerSignature(d, pubB64)).toBe(
      "producer_signed_rejected",
    );
  });

  it("rejects a producer_signed entry whose canonical bytes were altered", () => {
    const d = signedDetails();
    d[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY] = CANONICAL + " ";
    expect(reverifyEntryProducerSignature(d, pubB64)).toBe(
      "producer_signed_rejected",
    );
  });

  it("rejects a producer_signed entry signed by a DIFFERENT key", () => {
    const d = signedDetails();
    expect(
      reverifyEntryProducerSignature(
        d,
        toBase64url(ed25519.getPublicKey(ed25519.utils.randomPrivateKey())),
      ),
    ).toBe("producer_signed_rejected");
  });

  it("rejects a producer_signed entry whose seq was tampered (binding)", () => {
    const d = signedDetails();
    d.seq = SEQ + 1;
    expect(reverifyEntryProducerSignature(d, pubB64)).toBe(
      "producer_signed_rejected",
    );
  });

  it("a producer_signed entry with NO pinned key falls to channel basis (cannot verify)", () => {
    expect(reverifyEntryProducerSignature(signedDetails(), null)).toBe(
      "channel_authenticated",
    );
  });

  it("a channel_authenticated_unsigned entry is channel basis (even with a key)", () => {
    const d = {
      seq: 0,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED,
    };
    expect(reverifyEntryProducerSignature(d, pubB64)).toBe(
      "channel_authenticated",
    );
  });

  it("an entry with no basis field is channel basis (legacy)", () => {
    expect(reverifyEntryProducerSignature({ seq: 0 }, pubB64)).toBe(
      "channel_authenticated",
    );
  });

  it("non-record details are channel basis (never crash)", () => {
    expect(reverifyEntryProducerSignature(null, pubB64)).toBe(
      "channel_authenticated",
    );
    expect(reverifyEntryProducerSignature("x", pubB64)).toBe(
      "channel_authenticated",
    );
  });

  it("uses an injected verify fn when provided", () => {
    let called = false;
    const basis = reverifyEntryProducerSignature(signedDetails(), pubB64, () => {
      called = true;
      return { ok: false, reason: "stub" };
    });
    expect(called).toBe(true);
    expect(basis).toBe("producer_signed_rejected");
  });
});

describe("reverifyBasisCounts", () => {
  it("counts verified and channel bases; never counts a rejected forgery", () => {
    expect(reverifyBasisCounts("producer_signed_verified")).toBe(true);
    expect(reverifyBasisCounts("channel_authenticated")).toBe(true);
    expect(reverifyBasisCounts("producer_signed_rejected")).toBe(false);
  });
});
