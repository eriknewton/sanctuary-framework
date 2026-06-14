/**
 * Producer-signature CROSS-LANGUAGE byte-compat test (Slice L1 + Slice P
 * activation).
 *
 * The signature in the shared fixture was produced by the RUST daemon
 * (`ed25519-dalek` `ProducerSigner::sign_event`) and the verifying key was
 * published by the Rust daemon. Here the TS consumer/reader verifier
 * (`@noble/curves` via `verifyProducerSignature`) re-derives the signing bytes
 * and verifies that exact Rust signature against that exact Rust-published key.
 * A GREEN result proves the two languages hash and verify byte-identical input —
 * which is what makes the Slice P activation real: a real daemon-signed event
 * re-verifies in-process.
 *
 * The companion Rust test
 * (`castle-wall-daemon/tests/integration_producer_sig_cross_lang.rs`) verifies
 * the SAME fixture from the Rust side, so a layout drift in either language
 * fails in both suites.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";

import { verifyProducerSignature } from "../../../src/castle-wall/runtime/producer-signature.js";
import { CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";

interface CrossLangVector {
  pubkey_b64url: string;
  canonical: string;
  captured_at_unix_ms: number;
  seq: number;
  key_id: string;
  sig_b64url: string;
}

function loadVector(): CrossLangVector {
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = join(
    here,
    "..",
    "fixtures",
    "producer-sig-cross-lang-vector.json",
  );
  return JSON.parse(readFileSync(fixturePath, "utf8")) as CrossLangVector;
}

describe("castle-wall producer-signature : Rust→TS cross-language vector", () => {
  it("the TS verifier accepts a genuine Rust-daemon-signed event", () => {
    const v = loadVector();
    // The fixture's key id must match the v1 constant the verifier expects.
    expect(v.key_id).toBe(CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1);
    const verdict = verifyProducerSignature(
      {
        eventCanonicalJson: v.canonical,
        capturedAtUnixMs: v.captured_at_unix_ms,
        seq: v.seq,
        signatureB64url: v.sig_b64url,
        keyId: v.key_id,
      },
      v.pubkey_b64url,
    );
    expect(verdict).toEqual({ ok: true });
  });

  it("a one-byte change to the Rust-signed body fails (no re-encode drift)", () => {
    const v = loadVector();
    const verdict = verifyProducerSignature(
      {
        // Tamper the canonical body: the Rust signature must no longer verify,
        // proving the signature binds the EXACT bytes (not a re-canonicalized
        // object the two languages might normalize differently).
        eventCanonicalJson: v.canonical.replace("egress_blocked", "egress_allowed"),
        capturedAtUnixMs: v.captured_at_unix_ms,
        seq: v.seq,
        signatureB64url: v.sig_b64url,
        keyId: v.key_id,
      },
      v.pubkey_b64url,
    );
    expect(verdict.ok).toBe(false);
  });

  it("the Rust signature does not verify against a different key (forgery floor)", () => {
    const v = loadVector();
    // Flip a char near the START of the pubkey so the decoded 32 bytes genuinely
    // differ (a last-char flip can be padding-only and decode to the same bytes).
    const c = v.pubkey_b64url[1] === "A" ? "B" : "A";
    const tweaked = v.pubkey_b64url[0] + c + v.pubkey_b64url.slice(2);
    const verdict = verifyProducerSignature(
      {
        eventCanonicalJson: v.canonical,
        capturedAtUnixMs: v.captured_at_unix_ms,
        seq: v.seq,
        signatureB64url: v.sig_b64url,
        keyId: v.key_id,
      },
      tweaked,
    );
    expect(verdict.ok).toBe(false);
  });
});
