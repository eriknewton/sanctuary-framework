//! Producer-signature CROSS-LANGUAGE byte-compat test (Slice L1 + Slice P).
//!
//! Verifies the SAME shared fixture
//! (`server/test/castle-wall/fixtures/producer-sig-cross-lang-vector.json`) the
//! TS suite verifies, from the Rust side. The fixture's signature was produced
//! by this crate's `ProducerSigner` from a fixed seed; this test re-derives it
//! from that seed and asserts it matches the committed `sig_b64url`, and that
//! the committed signature verifies against the committed verifying key. If the
//! `producer_signing_bytes` layout drifts in either language, the vector fails
//! in BOTH suites.

use std::path::PathBuf;

use base64::Engine;
use castle_wall_daemon::ipc::producer_sig::{producer_signing_bytes, ProducerSigner};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;

fn fixture_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/castle-wall-daemon
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .join("server")
        .join("test")
        .join("castle-wall")
        .join("fixtures")
        .join("producer-sig-cross-lang-vector.json")
}

fn b64url_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .expect("valid base64url")
}

#[test]
fn rust_reproduces_and_verifies_the_cross_lang_vector() {
    let raw = std::fs::read_to_string(fixture_path()).expect("read fixture");
    let v: Value = serde_json::from_str(&raw).expect("parse fixture");

    let pubkey_b64 = v["pubkey_b64url"].as_str().expect("pubkey_b64url");
    let canonical = v["canonical"].as_str().expect("canonical");
    let ts = v["captured_at_unix_ms"].as_u64().expect("captured_at_unix_ms");
    let seq = v["seq"].as_u64().expect("seq");
    let sig_b64 = v["sig_b64url"].as_str().expect("sig_b64url");

    // 1) Re-derive the signature from the fixed seed and assert it matches the
    //    committed value (the fixture is reproducible, not hand-edited).
    let seed: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let signer = ProducerSigner::from_signing_key(SigningKey::from_bytes(&seed));
    assert_eq!(
        signer.public_key_b64url(),
        pubkey_b64,
        "fixture pubkey must match the fixed-seed signer"
    );
    assert_eq!(
        signer.sign_event(canonical, ts, seq),
        sig_b64,
        "fixture signature must reproduce from the fixed-seed signer"
    );

    // 2) Verify the committed signature against the committed key with the raw
    //    dalek verifier over the shared signing bytes (the cross-language check).
    let pub_bytes = b64url_decode(pubkey_b64);
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);
    let vk = VerifyingKey::from_bytes(&pub_arr).expect("verifying key");

    let sig_bytes = b64url_decode(sig_b64);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let message = producer_signing_bytes(canonical, ts, seq);
    vk.verify(&message, &signature)
        .expect("committed signature must verify against committed key");

    // 3) A tampered body must NOT verify (binds exact bytes, no re-encode drift).
    let tampered = producer_signing_bytes(&canonical.replace("egress_blocked", "egress_allowed"), ts, seq);
    assert!(
        vk.verify(&tampered, &signature).is_err(),
        "a tampered body must not verify"
    );
}
