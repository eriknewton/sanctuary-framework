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
  fromBase64url,
  toBase64url,
  type ProducerSignatureInput,
} from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../../src/castle-wall/constants.js";

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

  it("rejects an identity-key equation forgery accepted by permissive ZIP-215", () => {
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const scalarOne = new Uint8Array(32);
    scalarOne[0] = 1;
    const message = producerSigningBytes(CANONICAL, 1, 7);
    const forged = new Uint8Array(64);
    forged.set(ed25519.Point.BASE.toBytes(), 0);
    forged.set(scalarOne, 32);
    expect(ed25519.verify(forged, message, identity)).toBe(true);
    expect(
      verifyProducerSignature(
        {
          eventCanonicalJson: CANONICAL,
          capturedAtUnixMs: 1,
          seq: 7,
          signatureB64url: toBase64url(forged),
          keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        },
        toBase64url(identity)
      ).ok
    ).toBe(false);
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

describe("castle-wall producer-signature : fromBase64url ReDoS hardening", () => {
  // CodeQL js/polynomial-redos flagged the old `.replace(/=+$/, "")` strip:
  // the signature blob fed to fromBase64url is, by this module's threat model,
  // untrusted material being verified, and was decoded BEFORE any length check.
  // A long run of '=' followed by a non-'=' char drove the regex into O(n^2)
  // backtracking. The strip is now a linear reverse scan.

  it("decodes a pathological all-'=' input in bounded (linear) time", () => {
    // A 2,000,000-char run of '=' followed by a non-'=' char is the exact
    // shape that drove the old `=+$` regex super-linear (it took multiple
    // SECONDS at only 160k chars). The linear strip handles it in well under
    // the generous bound below; the value is then rejected on length by the
    // verifier, never accepted as a signature.
    const pathological = "=".repeat(2_000_000) + "x";
    const start = performance.now();
    // Decoding malformed base64 throws (atob on invalid input); either way the
    // call must RETURN/THROW quickly, not hang. We only assert it is bounded.
    try {
      fromBase64url(pathological);
    } catch {
      // expected for malformed base64 — the point is it completed fast.
    }
    const elapsedMs = performance.now() - start;
    // The old regex was ~9s at 160k chars (O(n^2)); at 2M chars it would be
    // wall-clock-infeasible. A linear scan finishes in single-digit ms. 1000ms
    // is a wide margin that still fails loudly if super-linear behavior returns.
    expect(elapsedMs).toBeLessThan(1000);
  });

  it("verifyProducerSignature rejects an oversized signature blob in bounded time", () => {
    const { pubB64 } = freshKeypair();
    const input: ProducerSignatureInput = {
      eventCanonicalJson: CANONICAL,
      capturedAtUnixMs: 1,
      seq: 7,
      // Attacker-shaped: a giant trailing-'=' run is the ReDoS payload. It must
      // fail closed (wrong length) quickly, never wedge the verifier.
      signatureB64url: "A" + "=".repeat(2_000_000),
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    };
    const start = performance.now();
    const verdict = verifyProducerSignature(input, pubB64);
    const elapsedMs = performance.now() - start;
    expect(verdict.ok).toBe(false);
    expect(elapsedMs).toBeLessThan(1000);
  });

  it("preserves exact decode behavior for valid signatures (no regression)", () => {
    // Round-trip every byte value through a real 64-byte Ed25519 signature so a
    // behavior change in the strip/padding path would surface as a mismatch.
    const { priv } = freshKeypair();
    const sigB64 = signEvent(priv, CANONICAL, 100, 7);
    const decoded = fromBase64url(sigB64);
    expect(decoded.length).toBe(64);
    // Re-encoding the decoded bytes reproduces the canonical base64url-no-pad
    // string: round-trip is identity for legitimate inputs.
    expect(toBase64url(decoded)).toBe(sigB64);
  });

  it("strips only the TRAILING '=' run, exactly like the prior regex", () => {
    // Trailing padding is tolerated and recomputed; embedded chars are intact.
    // 'AAAA' decodes to three zero bytes; trailing '=' must not change that.
    expect(Array.from(fromBase64url("AAAA"))).toEqual([0, 0, 0]);
    expect(Array.from(fromBase64url("AAAA=="))).toEqual([0, 0, 0]);
    // A genuine signature with explicit padding decodes identically to no-pad.
    const { priv } = freshKeypair();
    const sigNoPad = signEvent(priv, CANONICAL, 1, 1);
    const padded = sigNoPad + "=".repeat((4 - (sigNoPad.length % 4)) % 4);
    expect(Array.from(fromBase64url(padded))).toEqual(
      Array.from(fromBase64url(sigNoPad))
    );
  });
});

describe("castle-wall producer-signature : early signature-length bound", () => {
  // Defense-in-depth (review LOW): verifyProducerSignature bounds the
  // attacker-controlled signatureB64url BEFORE fromBase64url allocates, so a
  // large valid-base64 blob over daemon IPC is rejected without decoding ~3/4
  // its length into memory. The bound (128 chars) sits clearly above any real
  // 64-byte Ed25519 signature (88 padded / 86 unpadded base64url chars), so it
  // can reject no legitimate signature.

  it("rejects an oversized blob WITHOUT decoding it (fail-closed, bounded)", () => {
    const { pubB64 } = freshKeypair();
    // 200k chars of VALID base64 (not a trailing-'=' run): if the bound were
    // absent, fromBase64url would allocate ~150kB before the length check. With
    // the bound it is rejected on string length, never decoded.
    const oversized = "A".repeat(200_000);
    const input: ProducerSignatureInput = {
      eventCanonicalJson: CANONICAL,
      capturedAtUnixMs: 1,
      seq: 7,
      signatureB64url: oversized,
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    };
    const start = performance.now();
    const verdict = verifyProducerSignature(input, pubB64);
    const elapsedMs = performance.now() - start;
    expect(verdict).toEqual({
      ok: false,
      reason: "producer_signature_wrong_length",
    });
    expect(elapsedMs).toBeLessThan(1000);
  });

  it("admits a real signature (<=88 chars): the bound rejects no valid sig", () => {
    const { priv, pubB64 } = freshKeypair();
    const sigB64 = signEvent(priv, CANONICAL, 1718000000000, 7);
    // A genuine 64-byte Ed25519 signature base64url-no-pads to 86 chars, well
    // under the 128 ceiling. It must still verify.
    expect(sigB64.length).toBeLessThanOrEqual(88);
    const input: ProducerSignatureInput = {
      eventCanonicalJson: CANONICAL,
      capturedAtUnixMs: 1718000000000,
      seq: 7,
      signatureB64url: sigB64,
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    };
    expect(verifyProducerSignature(input, pubB64)).toEqual({ ok: true });
  });
});
