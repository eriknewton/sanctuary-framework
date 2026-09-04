//! Strict Ed25519 public-key admission and signature verification.
//!
//! `ed25519-dalek::VerifyingKey::from_bytes` accepts encodings outside the
//! prime-order subgroup, and its trait-level `Verifier::verify` intentionally
//! retains permissive compatibility behavior. Castle Wall keys are authority
//! roots, not consensus inputs, so every ingress uses the stricter contract:
//! canonical point encoding, non-small-order, torsion-free, and
//! `verify_strict` for signatures.

use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum StrictEd25519KeyError {
    #[error("wrong length (expected {expected}, got {actual})")]
    WrongLength { expected: usize, actual: usize },
    #[error("non-canonical or off-curve point encoding")]
    NonCanonical,
    #[error("small-order point is not an authority key")]
    SmallOrder,
    #[error("point is not in the prime-order subgroup")]
    NotPrimeOrder,
    #[error("Ed25519 verifying key rejected: {0}")]
    Dalek(String),
}

/// Parse a raw Ed25519 public key under Castle Wall's authority-key profile.
pub fn parse_strict_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, StrictEd25519KeyError> {
    if bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(StrictEd25519KeyError::WrongLength {
            expected: PUBLIC_KEY_LENGTH,
            actual: bytes.len(),
        });
    }
    let mut encoded = [0u8; PUBLIC_KEY_LENGTH];
    encoded.copy_from_slice(bytes);
    let point = CompressedEdwardsY(encoded)
        .decompress()
        .ok_or(StrictEd25519KeyError::NonCanonical)?;
    if point.compress().to_bytes() != encoded {
        return Err(StrictEd25519KeyError::NonCanonical);
    }
    if point.is_small_order() {
        return Err(StrictEd25519KeyError::SmallOrder);
    }
    if !point.is_torsion_free() {
        return Err(StrictEd25519KeyError::NotPrimeOrder);
    }
    VerifyingKey::from_bytes(&encoded).map_err(|err| StrictEd25519KeyError::Dalek(err.to_string()))
}

/// Verify with dalek's strict equation after strict public-key admission.
pub fn verify_strict_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &Signature,
) -> Result<(), StrictEd25519KeyError> {
    let key = parse_strict_verifying_key(public_key)?;
    key.verify_strict(message, signature)
        .map_err(|err| StrictEd25519KeyError::Dalek(err.to_string()))
}

/// Canonical Castle Wall identifier for a pinned manifest-signing key.
///
/// This preserves the already-shipped producer format while making the
/// previously decorative manifest field mechanically bound to the pin.
pub fn castle_wall_signing_key_id(public_key: &[u8]) -> Result<String, StrictEd25519KeyError> {
    parse_strict_verifying_key(public_key)?;
    let digest = Sha256::digest(public_key);
    let encoded = hex::encode(digest);
    Ok(encoded[..16].to_string())
}

/// One-release compatibility label emitted by the pre-hash publisher.
/// Verification may accept it during the documented migration window, but all
/// new publication continues to stamp [`castle_wall_signing_key_id`].
pub fn legacy_castle_wall_signing_key_id(
    public_key: &[u8],
) -> Result<String, StrictEd25519KeyError> {
    parse_strict_verifying_key(public_key)?;
    Ok(format!(
        "castle-wall:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{
        constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
        scalar::Scalar,
    };
    use ed25519_dalek::{Verifier, VerifyingKey};

    fn identity_forgery(message: &[u8]) -> ([u8; 32], Signature) {
        let mut public_key = [0u8; 32];
        public_key[0] = 1;
        let scalar = Scalar::from(42u64);
        let r = (scalar * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&scalar.to_bytes());
        let signature = Signature::from_bytes(&signature);
        let permissive = VerifyingKey::from_bytes(&public_key).expect("identity parses");
        assert!(
            permissive.verify(message, &signature).is_ok(),
            "regression must construct a signature accepted by the permissive equation"
        );
        (public_key, signature)
    }

    #[test]
    fn constructive_identity_forgery_is_rejected() {
        let message = b"arbitrary Castle Wall authority message";
        let (identity, signature) = identity_forgery(message);
        assert!(matches!(
            verify_strict_ed25519(&identity, message, &signature),
            Err(StrictEd25519KeyError::SmallOrder)
        ));
    }

    #[test]
    fn noncanonical_and_torsion_bearing_keys_are_rejected() {
        let mut noncanonical_identity = [0u8; 32];
        noncanonical_identity[0] = 1;
        noncanonical_identity[31] = 0x80;
        assert!(parse_strict_verifying_key(&noncanonical_identity).is_err());

        let mixed = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
            .compress()
            .to_bytes();
        assert!(!CompressedEdwardsY(mixed)
            .decompress()
            .unwrap()
            .is_small_order());
        assert!(matches!(
            parse_strict_verifying_key(&mixed),
            Err(StrictEd25519KeyError::NotPrimeOrder)
        ));
    }

    #[test]
    fn canonical_key_id_matches_cross_language_vector() {
        let public_key =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        assert_eq!(
            castle_wall_signing_key_id(&public_key).unwrap(),
            "21fe31dfa154a261"
        );
    }
}
