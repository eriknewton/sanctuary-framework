//! Contract fixtures only; no daemon boot, key loader, socket or service integration.
pub mod signer_contract;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use signer_contract::*;

pub fn strict_point(bytes: &[u8]) -> bool {
    let encoded: [u8; 32] = match bytes.try_into() { Ok(value) => value, Err(_) => return false };
    match CompressedEdwardsY(encoded).decompress() {
        Some(point) => point.compress().to_bytes() == encoded && !point.is_small_order() && point.is_torsion_free(),
        None => false,
    }
}

pub fn strict_encoding_profile(signature: &[u8], public_key: &[u8]) -> bool {
    if signature.len() != 64 || !strict_point(public_key) || !strict_point(&signature[..32]) { return false; }
    let scalar: [u8; 32] = signature[32..].try_into().expect("checked signature length");
    bool::from(curve25519_dalek::scalar::Scalar::from_canonical_bytes(scalar).is_some())
}

pub fn strict_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if !strict_encoding_profile(signature, public_key) { return false; }
    let bytes: &[u8; 32] = match public_key.try_into() { Ok(value) => value, Err(_) => return false };
    match (VerifyingKey::from_bytes(bytes), Signature::from_slice(signature)) {
        (Ok(key), Ok(sig)) => key.verify_strict(message, &sig).is_ok(),
        _ => false,
    }
}

pub fn role_kid(role: &str, epoch: u64, public_key: &[u8]) -> Option<String> {
    if epoch == 0 || epoch > 9007199254740991 || public_key.len() != 32 || !ROLE_REGISTRY.iter().any(|entry| entry.0 == role) { return None; }
    // Must match roleKid in server/src/signing/contract.ts, including canonical JSON and unpadded base64url.
    let body = json!({"v": 1, "role": role, "epoch": epoch, "public_key": URL_SAFE_NO_PAD.encode(public_key)});
    let mut hash = Sha256::new();
    hash.update(KID_DOMAIN.as_bytes());
    // Canonical encoding must not depend on serde map insertion order or feature unification.
    hash.update(crate::smb::jcs::encode(&body).ok()?.as_bytes());
    Some(format!("k1:sha256:{}", hex::encode(hash.finalize())))
}

/// Cryptographic contract only; typed payload and outer index checks belong to each future consumer.
pub fn verify_role(role: &str, epoch: u64, kid: &str, scheme: &str, record_kind: &str, preimage: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    // A legacy scheme refuses even if its signature verifies because it cannot name a K1 role grant.
    if scheme != ROLE_SIGNATURE_SCHEME || role_kid(role, epoch, public_key).as_deref() != Some(kid) { return false; }
    let entry = match ROLE_REGISTRY.iter().find(|entry| entry.0 == role) { Some(value) => value, None => return false };
    if preimage.len() > SIGNER_PREIMAGE_MAX_BYTES || entry.1.len() + preimage.len() > SIGNER_MESSAGE_MAX_BYTES { return false; }
    // Must match the registered signed record_kind selected by TypeScript adapters in signing/contract.ts.
    if !RECORD_KINDS.iter().any(|row| row.0 == role && row.1.contains(&record_kind)) { return false; }
    let body: serde_json::Value = match serde_json::from_slice(preimage) { Ok(value) => value, Err(_) => return false };
    // Overlapping payload schemas cannot grant the authority of another signed record kind.
    if body.get("record_kind").and_then(|value| value.as_str()) != Some(record_kind) { return false; }
    let mut message = entry.1.as_bytes().to_vec();
    message.extend_from_slice(preimage);
    strict_verify(&message, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Must match the complete public vectors in server/test/signing/strict-verifier.test.ts via the generator.
    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("public_vectors.json")).unwrap()
    }
    #[test]
    fn registered_kind_is_required_even_for_a_valid_signature() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let role = ROLE_REGISTRY[0].0;
        let public_key = key.verifying_key().to_bytes();
        let kid = role_kid(role, 1, &public_key).unwrap();
        for kind in ["append", "unregistered"] {
            let body = crate::smb::jcs::encode(&json!({"record_kind": kind})).unwrap();
            let message = [ROLE_REGISTRY[0].1.as_bytes(), body.as_bytes()].concat();
            let signature = key.sign(&message).to_bytes();
            assert_eq!(verify_role(role, 1, &kid, ROLE_SIGNATURE_SCHEME, kind, body.as_bytes(), &signature, &public_key), kind == "append");
        }
    }
    #[test]
    fn kid_encoding_uses_canonical_order() {
        // Must match roleKid in server/src/signing/contract.ts even when insertion order differs.
        let body: serde_json::Value = serde_json::from_str(r#"{"v":1,"role":"r","public_key":"p","epoch":2}"#).unwrap();
        assert_eq!(crate::smb::jcs::encode(&body).unwrap(), r#"{"epoch":2,"public_key":"p","role":"r","v":1}"#);
        assert!(include_str!("mod.rs").split("#[cfg(test)]").next().unwrap().contains("hash.update(crate::smb::jcs::encode(&body).ok()?.as_bytes())"));
    }
    #[test]
    fn identical_public_strict_vectors() {
        for vector in vectors().as_array().unwrap() {
            let decode = |key: &str| hex::decode(vector[key].as_str().unwrap()).unwrap();
            assert_eq!(strict_encoding_profile(&decode("signature"), &decode("public_key")), vector["valid"].as_bool().unwrap(), "encoding {}", vector["name"]);
            assert_eq!(strict_verify(&decode("message"), &decode("signature"), &decode("public_key")), vector["valid"].as_bool().unwrap(), "{}", vector["name"]);
            if let Some(kind) = vector["point_kind"].as_str() {
                let bytes = if kind == "A" { decode("public_key") } else { decode("signature")[..32].to_vec() };
                assert!(!strict_point(&bytes), "point gate {}", vector["name"]);
            }
        }
    }
    #[test]
    fn every_role_vector_and_legacy_refusal() {
        let rows: serde_json::Value = serde_json::from_str(include_str!("role_vectors.json")).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), ROLE_REGISTRY.len());
        for row in rows.as_array().unwrap() {
            let role = row["role"].as_str().unwrap();
            let key = hex::decode(row["public_key"].as_str().unwrap()).unwrap();
            let sig = hex::decode(row["signature"].as_str().unwrap()).unwrap();
            let body = hex::decode(row["preimage"].as_str().unwrap()).unwrap();
            let kid = row["kid"].as_str().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let kind = parsed["record_kind"].as_str().unwrap();
            assert_eq!(role_kid(role, 1, &key).unwrap(), kid);
            assert!(verify_role(role, 1, kid, ROLE_SIGNATURE_SCHEME, kind, &body, &sig, &key));
            assert!(!verify_role(role, 1, kid, "ed25519-v1", kind, &body, &sig, &key));
            assert!(!verify_role(role, 1, "cw-audit-producer-v1", ROLE_SIGNATURE_SCHEME, kind, &body, &sig, &key));
            for other_kind in RECORD_KINDS.iter().find(|row| row.0 == role).unwrap().1 {
                if *other_kind != kind { assert!(!verify_role(role, 1, kid, ROLE_SIGNATURE_SCHEME, other_kind, &body, &sig, &key)); }
            }
            assert!(!verify_role(role, 1, kid, ROLE_SIGNATURE_SCHEME, "unregistered", &body, &sig, &key));
            for other in ROLE_REGISTRY { if other.0 != role { assert!(!verify_role(other.0, 1, kid, ROLE_SIGNATURE_SCHEME, kind, &body, &sig, &key)); } }
        }
    }
}
