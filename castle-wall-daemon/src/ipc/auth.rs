//! IPC authentication: Ed25519 challenge-response over the UDS handshake,
//! plus SO_PEERCRED on Linux to bind the connection to a specific UID.
//!
//! The privilege boundary is asymmetric. The daemon proves nothing about
//! itself other than holding the pinned fortress public key; Sanctuary main
//! proves it controls the fortress identity by signing the daemon-issued
//! 32-byte nonce. Mirrors scope-lock §5 Option A. SO_PEERCRED gives the
//! daemon a kernel-attested operator UID; the Ed25519 layer binds that UID
//! to the legitimate fortress-key holder.

use std::path::Path;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use rand_core::{OsRng, RngCore};

use crate::ipc::messages::IpcMessage;

/// Challenge-response nonce length per scope-lock §5.
pub const CHALLENGE_NONCE_BYTES: usize = 32;

/// Errors emitted by the auth layer.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("pinned public key file unreadable: {0}")]
    PinnedKeyIo(String),
    #[error("pinned public key wrong length (expected {expected}, got {actual})")]
    PinnedKeyLength { expected: usize, actual: usize },
    #[error("handshake response was not a HandshakeResponse message")]
    WrongMessageType,
    #[error("nonce signature base64url decode failed: {0}")]
    SignatureDecode(String),
    #[error("nonce signature wrong length (expected {expected}, got {actual})")]
    SignatureLength { expected: usize, actual: usize },
    #[error("nonce signature verification failed against pinned key")]
    SignatureMismatch,
    #[error("pinned public key bytes are not a valid Ed25519 key: {0}")]
    PinnedKeyMalformed(String),
    #[error("peer credential check failed: {0}")]
    PeerCred(String),
    #[error("connecting peer UID {got} does not match expected operator UID {expected}")]
    PeerUidMismatch { expected: u32, got: u32 },
}

/// Load the daemon's TOFU-pinned fortress public key from disk.
/// Format: 32 raw bytes (the Ed25519 verifying-key bytes); installed by
/// the wrap CLI on first boot. Cross-signed rotation is handled at the
/// manifest layer (PR 2b Checkpoint 2), not here.
pub fn load_pinned_public_key(path: &Path) -> Result<Vec<u8>, AuthError> {
    let bytes = std::fs::read(path).map_err(|err| AuthError::PinnedKeyIo(err.to_string()))?;
    if bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(AuthError::PinnedKeyLength {
            expected: PUBLIC_KEY_LENGTH,
            actual: bytes.len(),
        });
    }
    // Validate the bytes parse to a valid VerifyingKey before returning.
    let mut pk = [0u8; PUBLIC_KEY_LENGTH];
    pk.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&pk).map_err(|err| AuthError::PinnedKeyMalformed(err.to_string()))?;
    Ok(bytes)
}

/// Generate a fresh 32-byte challenge nonce from the OS RNG.
pub fn generate_challenge_nonce() -> [u8; CHALLENGE_NONCE_BYTES] {
    let mut nonce = [0u8; CHALLENGE_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encode a nonce for transport over the wire.
pub fn encode_nonce_b64url(nonce: &[u8; CHALLENGE_NONCE_BYTES]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
}

/// Identity asserted by a successful handshake. The daemon does not bind
/// `signing_key_id` to authority; it is recorded for audit.
#[derive(Debug, Clone)]
pub struct HandshakeIdentity {
    pub fortress_id: String,
    pub signing_key_id: String,
}

/// Verify a handshake response against the original challenge nonce. The
/// signing input is the raw nonce bytes (NOT the base64url string).
pub fn verify_handshake_response(
    response: &IpcMessage,
    expected_nonce: &[u8; CHALLENGE_NONCE_BYTES],
    pinned_public_key: &[u8],
) -> Result<HandshakeIdentity, AuthError> {
    let (fortress_id, signing_key_id, signature_b64url) = match response {
        IpcMessage::HandshakeResponse {
            fortress_id,
            signing_key_id,
            nonce_signature_b64url,
        } => (
            fortress_id.clone(),
            signing_key_id.clone(),
            nonce_signature_b64url.clone(),
        ),
        _ => return Err(AuthError::WrongMessageType),
    };

    if pinned_public_key.len() != PUBLIC_KEY_LENGTH {
        return Err(AuthError::PinnedKeyLength {
            expected: PUBLIC_KEY_LENGTH,
            actual: pinned_public_key.len(),
        });
    }

    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64url.as_bytes())
        .map_err(|err| AuthError::SignatureDecode(err.to_string()))?;
    if signature_bytes.len() != SIGNATURE_LENGTH {
        return Err(AuthError::SignatureLength {
            expected: SIGNATURE_LENGTH,
            actual: signature_bytes.len(),
        });
    }

    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let mut pk_arr = [0u8; PUBLIC_KEY_LENGTH];
    pk_arr.copy_from_slice(pinned_public_key);
    let key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|err| AuthError::PinnedKeyMalformed(err.to_string()))?;

    key.verify(expected_nonce, &signature)
        .map_err(|_| AuthError::SignatureMismatch)?;

    Ok(HandshakeIdentity {
        fortress_id,
        signing_key_id,
    })
}

/// Look up the connecting peer's UID via SO_PEERCRED on Linux. On other
/// platforms this returns an error; production deployment is Linux only,
/// but unit tests on macOS use the `expect_uid: None` path which skips this
/// check.
#[cfg(target_os = "linux")]
pub fn peer_uid_for_stream(stream: &std::os::unix::net::UnixStream) -> Result<u32, AuthError> {
    use nix::sys::socket::sockopt::PeerCredentials;
    use nix::sys::socket::getsockopt;
    use std::os::fd::{AsRawFd, BorrowedFd};
    let fd = stream.as_raw_fd();
    // SAFETY: the &UnixStream borrow keeps the fd alive for the duration
    // of this call; getsockopt reads SO_PEERCRED without retaining the fd.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let cred = getsockopt(&borrowed, PeerCredentials)
        .map_err(|err| AuthError::PeerCred(err.to_string()))?;
    Ok(cred.uid())
}

#[cfg(not(target_os = "linux"))]
pub fn peer_uid_for_stream(_stream: &std::os::unix::net::UnixStream) -> Result<u32, AuthError> {
    Err(AuthError::PeerCred(
        "SO_PEERCRED is only available on Linux".to_string(),
    ))
}

/// Optionally enforce that the connecting peer's UID matches the operator
/// UID configured at install time. Returns the actual peer UID if known.
pub fn enforce_peer_uid(
    stream: &std::os::unix::net::UnixStream,
    expected_uid: Option<u32>,
) -> Result<Option<u32>, AuthError> {
    match expected_uid {
        None => Ok(None),
        Some(expected) => {
            let got = peer_uid_for_stream(stream)?;
            if got != expected {
                Err(AuthError::PeerUidMismatch { expected, got })
            } else {
                Ok(Some(got))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn pinned_key_round_trip() {
        let dir = TempDir::new().unwrap();
        let signing = SigningKey::generate(&mut OsRng);
        let path = dir.path().join("pinned.key");
        fs::write(&path, signing.verifying_key().to_bytes()).unwrap();
        let bytes = load_pinned_public_key(&path).unwrap();
        assert_eq!(bytes.len(), PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn pinned_key_rejects_wrong_length() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("short.key");
        fs::write(&path, b"too short").unwrap();
        let err = load_pinned_public_key(&path).unwrap_err();
        assert!(matches!(err, AuthError::PinnedKeyLength { .. }));
    }

    #[test]
    fn pinned_key_rejects_missing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("absent.key");
        let err = load_pinned_public_key(&path).unwrap_err();
        assert!(matches!(err, AuthError::PinnedKeyIo(_)));
    }

    #[test]
    fn nonce_is_32_bytes_and_random() {
        let a = generate_challenge_nonce();
        let b = generate_challenge_nonce();
        assert_eq!(a.len(), CHALLENGE_NONCE_BYTES);
        assert_ne!(a, b);
    }

    #[test]
    fn happy_path_handshake_verifies() {
        let signing = SigningKey::generate(&mut OsRng);
        let public = signing.verifying_key().to_bytes();
        let nonce = generate_challenge_nonce();
        let signature = signing.sign(&nonce);
        let response = IpcMessage::HandshakeResponse {
            fortress_id: "deadbeef".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_bytes()),
        };
        let identity = verify_handshake_response(&response, &nonce, &public).unwrap();
        assert_eq!(identity.fortress_id, "deadbeef");
    }

    #[test]
    fn signature_against_other_key_rejected() {
        let signing = SigningKey::generate(&mut OsRng);
        let other_signing = SigningKey::generate(&mut OsRng);
        let pinned = signing.verifying_key().to_bytes();
        let nonce = generate_challenge_nonce();
        let signature = other_signing.sign(&nonce);
        let response = IpcMessage::HandshakeResponse {
            fortress_id: "deadbeef".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_bytes()),
        };
        let err = verify_handshake_response(&response, &nonce, &pinned).unwrap_err();
        assert!(matches!(err, AuthError::SignatureMismatch));
    }

    #[test]
    fn signature_over_wrong_nonce_rejected() {
        let signing = SigningKey::generate(&mut OsRng);
        let pinned = signing.verifying_key().to_bytes();
        let issued = generate_challenge_nonce();
        let attacker_nonce = generate_challenge_nonce();
        let signature = signing.sign(&attacker_nonce);
        let response = IpcMessage::HandshakeResponse {
            fortress_id: "deadbeef".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_bytes()),
        };
        let err = verify_handshake_response(&response, &issued, &pinned).unwrap_err();
        assert!(matches!(err, AuthError::SignatureMismatch));
    }

    #[test]
    fn wrong_message_type_rejected() {
        let signing = SigningKey::generate(&mut OsRng);
        let pinned = signing.verifying_key().to_bytes();
        let nonce = generate_challenge_nonce();
        let bogus = IpcMessage::HandshakeChallenge {
            nonce_b64url: encode_nonce_b64url(&nonce),
        };
        let err = verify_handshake_response(&bogus, &nonce, &pinned).unwrap_err();
        assert!(matches!(err, AuthError::WrongMessageType));
    }

    #[test]
    fn malformed_signature_decode_rejected() {
        let signing = SigningKey::generate(&mut OsRng);
        let pinned = signing.verifying_key().to_bytes();
        let nonce = generate_challenge_nonce();
        let response = IpcMessage::HandshakeResponse {
            fortress_id: "deadbeef".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: "!!!not-base64!!!".to_string(),
        };
        let err = verify_handshake_response(&response, &nonce, &pinned).unwrap_err();
        assert!(matches!(err, AuthError::SignatureDecode(_)));
    }
}
