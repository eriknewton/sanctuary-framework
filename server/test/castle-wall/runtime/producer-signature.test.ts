/**
 * Slice L1 producer-signature verification tests (consumer side).
 *
 * Covers the pure verifier and its fail-closed behavior, plus the byte-exact
 * cross-language signing-bytes contract with the Rust daemon.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  producerSigningBytes,
  verifyProducerSignature,
  type ProducerSignatureInput,
} from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../../src/castle-wall/constants.js";

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function freshKeypair(): { priv: Uint8Array; pubB64: string } {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  return { priv, pubB64: toBase64url(pub) };
}

function signEvent(
  priv: Uint8Array,
  canonical: string,
  ts: number,
  seq: number
): string {
  const sig = ed25519.sign(producerSigningBytes(canonical, ts, seq), priv);
  return toBase64url(sig);
}

const CANONICAL = '{"event_type":"egress_blocked","seq":7}';

describe("castle-wall producer-signature : signing bytes", () => {
  it("is prefix-bound and changes with seq, timestamp, and body", () => {
    const a = producerSigningBytes(CANONICAL, 1000, 7);
    const b = producerSigningBytes(CANONICAL, 1000, 7);
    expect(a).toEqual(b);
    expect(a).not.toEqual(producerSigningBytes(CANONICAL, 1000, 8));
    expect(a).not.toEqual(producerSigningBytes(CANONICAL, 1001, 7));
    expect(a).not.toEqual(producerSigningBytes("{}", 1000, 7));
    const prefixBytes = new TextEncoder().encode(
      CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX
    );
    expect(Array.from(a.slice(0, prefixBytes.length))).toEqual(
      Array.from(prefixBytes)
    );
  });

  it("matches the documented newline-delimited layout exactly", () => {
    const bytes = producerSigningBytes("BODY", 42, 9);
    const text = new TextDecoder().decode(bytes);
    expect(text).toBe(`${CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX}BODY\n42\n9`);
  });
});

describe("castle-wall producer-signature : verifyProducerSignature", () => {
  it("accepts a genuine signature over seq/ts/canonical", () => {
    const { priv, pubB64 } = freshKeypair();
    const input: ProducerSignatureInput = {
      eventCanonicalJson: CANONICAL,
      capturedAtUnixMs: 1718000000000,
      seq: 7,
      signatureB64url: signEvent(priv, CANONICAL, 1718000000000, 7),
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    };
    expect(verifyProducerSignature(input, pubB64)).toEqual({ ok: true });
  });

  it("fails closed on a missing signature", () => {
    const { pubB64 } = freshKeypair();
    const verdict = verifyProducerSignature(
      {
        eventCanonicalJson: CANONICAL,
        capturedAtUnixMs: 1,
        seq: 7,
        signatureB64url: undefined,
        keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      },
      pubB64
    );
    expect(verdict.ok).toBe(false);
  });

  it("fails closed on a signature from a DIFFERENT key (forgery)", () => {
    const victim = freshKeypair();
    const forger = freshKeypair();
    // Forger signs the exact same message with their own key.
    const input: ProducerSignatureInput = {
      eventCanonicalJson: CANONICAL,
      capturedAtUnixMs: 5,
      seq: 7,
      signatureB64url: signEvent(forger.priv, CANONICAL, 5, 7),
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    };
    // Verifying against the VICTIM (pinned) key must fail: the forger does not
    // hold the pinned producer private key, so it cannot mint a valid sig.
    const verdict = verifyProducerSignature(input, victim.pubB64);
    expect(verdict.ok).toBe(false);
  });

  it("fails closed on REPLAY: a genuine signature reused at a different seq", () => {
    const { priv, pubB64 } = freshKeypair();
    const sigAtSeq7 = signEvent(priv, CANONICAL, 100, 7);
    // Replay the seq-7 signature claiming seq 8 (a forger trying to re-arm with
    // a captured old signature) — the seq is part of the signed message, so it
    // does not verify.
    const replayed: ProducerSignatureInput = {
      eventCanonicalJson: CANONICAL,
      capturedAtUnixMs: 100,
      seq: 8,
      signatureB64url: sigAtSeq7,
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    };
    expect(verifyProducerSignature(replayed, pubB64).ok).toBe(false);
  });

  it("fails closed on a key-id mismatch", () => {
    const { priv, pubB64 } = freshKeypair();
    const input: ProducerSignatureInput = {
      eventCanonicalJson: CANONICAL,
      capturedAtUnixMs: 1,
      seq: 7,
      signatureB64url: signEvent(priv, CANONICAL, 1, 7),
      keyId: "some-other-key",
    };
    expect(verifyProducerSignature(input, pubB64).ok).toBe(false);
  });

  it("fails closed on a malformed pinned key", () => {
    const { priv } = freshKeypair();
    const input: ProducerSignatureInput = {
      eventCanonicalJson: CANONICAL,
      capturedAtUnixMs: 1,
      seq: 7,
      signatureB64url: signEvent(priv, CANONICAL, 1, 7),
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    };
    expect(verifyProducerSignature(input, "!!!not-base64!!!").ok).toBe(false);
  });

  it("fails closed on a tampered body", () => {
    const { priv, pubB64 } = freshKeypair();
    const sig = signEvent(priv, CANONICAL, 1, 7);
    const input: ProducerSignatureInput = {
      eventCanonicalJson: '{"event_type":"egress_blocked","seq":7,"tampered":true}',
      capturedAtUnixMs: 1,
      seq: 7,
      signatureB64url: sig,
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    };
    expect(verifyProducerSignature(input, pubB64).ok).toBe(false);
  });
});
