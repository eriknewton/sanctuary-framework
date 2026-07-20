/**
 * Unit tests for the read-side re-verification helper (Slice R core).
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  reverifyEntryProducerSignature,
  enforcementEntryCounts,
  signedCanonicalSubjectIssue,
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

function auditTokenForRuid(uid: number): string {
  const vals = [
    0xffffffff,
    uid,
    uid,
    uid,
    uid,
    0x00000269,
    0x000186ae,
    0x00000566,
  ];
  return vals
    .map((value) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
      return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    })
    .join("");
}

function signedDetails(canonical: string = CANONICAL): Record<string, unknown> {
  const sig = ed25519.sign(producerSigningBytes(canonical, TS, SEQ), priv);
  return {
    seq: SEQ,
    [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
    [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
    [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: TS,
    [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  };
}

const basisOf = (...args: Parameters<typeof reverifyEntryProducerSignature>) =>
  reverifyEntryProducerSignature(...args).basis;

describe("reverifyEntryProducerSignature", () => {
  it("verifies a genuine signed entry against the pinned key + carries signed time", () => {
    const result = reverifyEntryProducerSignature(signedDetails(), pubB64);
    expect(result.basis).toBe("producer_signed_verified");
    // The signature-bound capture time is returned so the reader judges freshness
    // from it, not the forgeable top-level audit timestamp.
    expect(result.signedCapturedAtMs).toBe(TS);
  });

  it("rejects a producer_signed entry with a missing signature (key present)", () => {
    const d = signedDetails();
    delete d[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY];
    expect(basisOf(d, pubB64)).toBe("producer_signed_rejected");
  });

  it("rejects a producer_signed entry whose canonical bytes were altered", () => {
    const d = signedDetails();
    d[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY] = CANONICAL + " ";
    expect(basisOf(d, pubB64)).toBe("producer_signed_rejected");
  });

  it("rejects a producer_signed entry signed by a DIFFERENT key", () => {
    const d = signedDetails();
    expect(
      basisOf(
        d,
        toBase64url(ed25519.getPublicKey(ed25519.utils.randomPrivateKey())),
      ),
    ).toBe("producer_signed_rejected");
  });

  it("rejects a producer_signed entry whose seq was tampered (binding)", () => {
    const d = signedDetails();
    d.seq = SEQ + 1;
    expect(basisOf(d, pubB64)).toBe("producer_signed_rejected");
  });

  it("a producer_signed entry with NO pinned key falls to channel basis (cannot verify)", () => {
    const result = reverifyEntryProducerSignature(signedDetails(), null);
    expect(result.basis).toBe("channel_authenticated");
    // No signed time is asserted on the channel basis.
    expect(result.signedCapturedAtMs).toBeNull();
  });

  it("a channel_authenticated_unsigned entry is channel basis (even with a key)", () => {
    const d = {
      seq: 0,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED,
    };
    expect(basisOf(d, pubB64)).toBe("channel_authenticated");
  });

  it("an entry with no basis field is channel basis (legacy)", () => {
    expect(basisOf({ seq: 0 }, pubB64)).toBe("channel_authenticated");
  });

  it("non-record details are channel basis (never crash)", () => {
    expect(basisOf(null, pubB64)).toBe("channel_authenticated");
    expect(basisOf("x", pubB64)).toBe("channel_authenticated");
  });

  it("uses an injected verify fn when provided", () => {
    let called = false;
    const basis = basisOf(signedDetails(), pubB64, () => {
      called = true;
      return { ok: false, reason: "stub" };
    });
    expect(called).toBe(true);
    expect(basis).toBe("producer_signed_rejected");
  });

  it("fails closed when a signed macOS audit-token binding is present but unresolvable", () => {
    const canonical = JSON.stringify({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "LIE",
      details: { agent_id: auditTokenForRuid(0) },
    });
    const details = signedDetails(canonical);
    const result = reverifyEntryProducerSignature(
      details,
      pubB64,
      undefined,
      "fortress:test",
    );

    expect(result.basis).toBe("producer_signed_verified");
    expect(result.signedIdentityId).toBeNull();
  });

  it("uses a canonical signed identity_id for the expected fortress", () => {
    const canonical = JSON.stringify({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress:test/uid-503",
      details: { dest_host: "api.example" },
    });
    const result = reverifyEntryProducerSignature(
      signedDetails(canonical),
      pubB64,
      undefined,
      "fortress:test",
    );

    expect(result.basis).toBe("producer_signed_verified");
    expect(result.signedIdentityId).toBe("fortress:test/uid-503");
  });

  it("rejects a non-canonical 64-hex signed identity_id instead of reinterpreting it as a macOS audit token", () => {
    const hexIdentity = auditTokenForRuid(503);
    const canonical = JSON.stringify({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: hexIdentity,
      details: { dest_host: "api.example" },
    });
    const result = reverifyEntryProducerSignature(
      signedDetails(canonical),
      pubB64,
      undefined,
      "fortress:test",
    );

    expect(result.basis).toBe("producer_signed_verified");
    expect(result.signedIdentityId).toBeNull();
  });

  it("rejects old Linux agent-name signed identity_id values as pre-canonical evidence", () => {
    const canonical = JSON.stringify({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "agent-1",
      details: { dest_host: "api.example" },
    });
    const details = signedDetails(canonical);
    const result = reverifyEntryProducerSignature(
      details,
      pubB64,
      undefined,
      "fortress:test",
    );

    expect(result.basis).toBe("producer_signed_verified");
    expect(result.signedIdentityId).toBeNull();
    expect(signedCanonicalSubjectIssue(details, "fortress:test")).toBe(
      "pre_canonical_linux_agent_name",
    );
  });

  it("rejects signed identity_id values from a different fortress", () => {
    const canonical = JSON.stringify({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress:other/uid-503",
      details: { dest_host: "api.example" },
    });
    const details = signedDetails(canonical);
    const result = reverifyEntryProducerSignature(
      details,
      pubB64,
      undefined,
      "fortress:test",
    );

    expect(result.basis).toBe("producer_signed_verified");
    expect(result.signedIdentityId).toBeNull();
    expect(signedCanonicalSubjectIssue(details, "fortress:test")).toBeNull();
  });

  it("derives a canonical signed identity_id without any persisted selector", () => {
    const canonical = JSON.stringify({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress:test/uid-503",
      details: { dest_host: "api.example" },
    });
    const details = signedDetails(canonical);

    const result = reverifyEntryProducerSignature(
      details,
      pubB64,
      undefined,
      "fortress:test",
    );

    expect(result.basis).toBe("producer_signed_verified");
    expect(result.signedIdentityId).toBe("fortress:test/uid-503");
  });

  it("falls back to the signed macOS audit token when signed identity_id is not canonical", () => {
    const canonical = JSON.stringify({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "macos-extension",
      details: { agent_id: auditTokenForRuid(503) },
    });
    const details = signedDetails(canonical);

    const result = reverifyEntryProducerSignature(
      details,
      pubB64,
      undefined,
      "fortress:test",
    );

    expect(result.basis).toBe("producer_signed_verified");
    expect(result.signedIdentityId).toBe("fortress:test/uid-503");
  });

  it("prefers a canonical signed identity_id over a macOS-looking signed details.agent_id", () => {
    const canonical = JSON.stringify({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress:test/uid-504",
      details: { agent_id: auditTokenForRuid(503) },
    });

    const result = reverifyEntryProducerSignature(
      signedDetails(canonical),
      pubB64,
      undefined,
      "fortress:test",
    );

    expect(result.basis).toBe("producer_signed_verified");
    expect(result.signedIdentityId).toBe("fortress:test/uid-504");
  });
});

describe("enforcementEntryCounts", () => {
  it("KEY PRESENT: only producer_signed_verified counts (channel/forged never count)", () => {
    expect(enforcementEntryCounts("producer_signed_verified", true)).toBe(true);
    expect(enforcementEntryCounts("channel_authenticated", true)).toBe(false);
    expect(enforcementEntryCounts("producer_signed_rejected", true)).toBe(false);
  });

  it("NO KEY: channel basis counts (honest floor); a rejected forgery cannot occur but never counts", () => {
    expect(enforcementEntryCounts("channel_authenticated", false)).toBe(true);
    expect(enforcementEntryCounts("producer_signed_verified", false)).toBe(true);
    expect(enforcementEntryCounts("producer_signed_rejected", false)).toBe(false);
  });
});
