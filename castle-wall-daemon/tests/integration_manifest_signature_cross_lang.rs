//! Manifest-signature cross-language fixtures (TS signer -> Rust verifier).
//!
//! Loads `server/test/castle-wall/fixtures/manifest-operator-baseline-cross-lang.json`,
//! whose signatures are produced by the TS manifest publisher over TS
//! canonical-JSON bytes. Rust verifies the exact same signed bodies through
//! its typed `AllowlistManifest` path, catching additive field mirror gaps.

use std::path::PathBuf;

use base64::Engine;
use castle_wall_daemon::manifest::canonical_json::canonicalize_to_bytes;
use castle_wall_daemon::manifest::verify::{
    verify_manifest_signature, SignedManifest, VerifyResult,
};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ManifestSignatureFixture {
    test_public_key_b64url: String,
    cases: Vec<ManifestSignatureCase>,
}

#[derive(Debug, Deserialize)]
struct ManifestSignatureCase {
    name: String,
    signed_manifest: SignedManifest,
    expected_canonical_json_b64: String,
    expected_canonical_json_hex: String,
    test_signature_b64url: String,
}

fn fixture_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/castle-wall-daemon
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("server")
        .join("test")
        .join("castle-wall")
        .join("fixtures")
        .join("manifest-operator-baseline-cross-lang.json")
}

fn load_fixture() -> ManifestSignatureFixture {
    let path = fixture_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("parse manifest-operator-baseline-cross-lang.json")
}

fn decode_public_key(b64url: &str) -> [u8; PUBLIC_KEY_LENGTH] {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64url.as_bytes())
        .expect("public key base64url");
    assert_eq!(decoded.len(), PUBLIC_KEY_LENGTH);
    let mut out = [0u8; PUBLIC_KEY_LENGTH];
    out.copy_from_slice(&decoded);
    out
}

fn fixture_case<'a>(
    fixture: &'a ManifestSignatureFixture,
    name: &str,
) -> &'a ManifestSignatureCase {
    fixture
        .cases
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("fixture case not found: {name}"))
}

fn assert_rust_canonical_bytes_match_fixture(case: &ManifestSignatureCase) {
    let value = serde_json::to_value(&case.signed_manifest.manifest).expect("serialize manifest");
    let canonical = canonicalize_to_bytes(&value).expect("canonicalize manifest");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&canonical),
        case.expected_canonical_json_b64,
        "{} canonical b64",
        case.name
    );
    assert_eq!(
        hex::encode(&canonical),
        case.expected_canonical_json_hex,
        "{} canonical hex",
        case.name
    );
}

#[test]
fn ts_signed_manifest_without_operator_baseline_still_verifies() {
    let fixture = load_fixture();
    let public_key = decode_public_key(&fixture.test_public_key_b64url);
    let case = fixture_case(&fixture, "without-operator-baseline");

    assert_eq!(
        case.signed_manifest.signature.signature_b64url,
        case.test_signature_b64url
    );
    assert_eq!(
        verify_manifest_signature(&case.signed_manifest, &public_key),
        VerifyResult::Ok
    );
    assert_rust_canonical_bytes_match_fixture(case);

    let value = serde_json::to_value(&case.signed_manifest.manifest).expect("serialize manifest");
    assert!(
        value.get("operator_baseline").is_none(),
        "absent operator_baseline must stay omitted, not serialized as null"
    );
}

#[test]
fn ts_signed_manifest_with_operator_baseline_verifies() {
    let fixture = load_fixture();
    let public_key = decode_public_key(&fixture.test_public_key_b64url);
    let case = fixture_case(&fixture, "with-operator-baseline");

    assert_eq!(
        case.signed_manifest.signature.signature_b64url,
        case.test_signature_b64url
    );
    assert_eq!(
        verify_manifest_signature(&case.signed_manifest, &public_key),
        VerifyResult::Ok
    );
    assert_rust_canonical_bytes_match_fixture(case);
}

#[test]
fn ts_signed_manifest_with_empty_operator_baseline_verifies() {
    let fixture = load_fixture();
    let public_key = decode_public_key(&fixture.test_public_key_b64url);
    let case = fixture_case(&fixture, "empty-operator-baseline");

    assert_eq!(
        case.signed_manifest.signature.signature_b64url,
        case.test_signature_b64url
    );
    assert_eq!(
        verify_manifest_signature(&case.signed_manifest, &public_key),
        VerifyResult::Ok
    );
    assert_rust_canonical_bytes_match_fixture(case);
}
