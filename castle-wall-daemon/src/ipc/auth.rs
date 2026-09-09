//! IPC authentication: Ed25519 challenge-response over the UDS handshake,
//! plus SO_PEERCRED on Linux to bind the connection to a specific UID.
//!
//! The privilege boundary is asymmetric. Sanctuary main proves it controls
//! the fortress identity by signing the daemon-issued challenge and complete
//! negotiated context. The daemon is authenticated operationally by the
//! root-owned socket path and pre-provisioned system-service boundary; a
//! public verification key is not proof of daemon identity. SO_PEERCRED gives
//! the daemon a kernel-attested peer UID, while Ed25519 binds that UID to the
//! legitimate fortress-key holder.

use std::path::Path;

use base64::Engine;
use ed25519_dalek::{Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use rand_core::{OsRng, RngCore};

use crate::crypto::parse_strict_verifying_key;
use crate::ipc::messages::IpcMessage;

/// Challenge-response nonce length per scope-lock §5.
pub const CHALLENGE_NONCE_BYTES: usize = 32;
const HANDSHAKE_CONTEXT_DOMAIN: &[u8] = b"sanctuary-castle-wall-ipc-handshake-v1\0";

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
    #[error("handshake fortress id {got:?} does not match configured fortress {expected:?}")]
    FortressIdMismatch { expected: String, got: String },
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
    parse_strict_verifying_key(&bytes)
        .map_err(|err| AuthError::PinnedKeyMalformed(err.to_string()))?;
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

/// Identity asserted by a successful handshake. `signing_key_id` is covered
/// by the pinned-key signature (so it cannot be relabelled in transit), but it
/// remains an audit label rather than an independent authorization source.
#[derive(Debug, Clone)]
pub struct HandshakeIdentity {
    pub fortress_id: String,
    pub signing_key_id: String,
    /// Protocol version the peer declared, or `None` for a pre-v2 peer.
    pub peer_protocol_version: Option<u32>,
    /// Capability tokens the peer declared it can PARSE. This carries NO
    /// authority: the handshake signature authenticates this declared context,
    /// while every authorization decision stays on the kernel peer UID check in
    /// `server.rs`. Its only use is to withhold a newer response shape from a
    /// peer that would not understand it.
    pub peer_capabilities: Vec<String>,
}

impl HandshakeIdentity {
    /// Does the peer accept messages guarded by `capability`?
    ///
    /// Absence is decided FAIL-COMPATIBLE, not fail-closed: an unlisted
    /// capability means "send this peer the older shape", which is the safe
    /// direction because the older shape is what every previously-shipped
    /// consumer was built against. It is never a security decision.
    pub fn accepts(&self, capability: &str) -> bool {
        self.peer_capabilities.iter().any(|c| c == capability)
    }
}

/// Construct the unambiguous, domain-separated handshake signing input.
///
/// Every peer-controlled field that changes how the authenticated connection
/// is interpreted is length-prefixed and covered.  The former nonce-only
/// signature allowed a captured valid response to have its fortress id,
/// signing-key label, protocol, or capabilities rewritten in transit.
pub fn handshake_signing_bytes(
    nonce: &[u8; CHALLENGE_NONCE_BYTES],
    fortress_id: &str,
    signing_key_id: &str,
    protocol_version: Option<u32>,
    capabilities: &[String],
) -> Vec<u8> {
    fn push_field(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }

    let mut out = Vec::new();
    out.extend_from_slice(HANDSHAKE_CONTEXT_DOMAIN);
    out.extend_from_slice(nonce);
    push_field(&mut out, fortress_id.as_bytes());
    push_field(&mut out, signing_key_id.as_bytes());
    out.extend_from_slice(&protocol_version.unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&(capabilities.len() as u32).to_be_bytes());
    for capability in capabilities {
        push_field(&mut out, capability.as_bytes());
    }
    out
}

/// Verify a handshake response against the original challenge and the daemon's
/// configured fortress.  The entire negotiated context is signed.
pub fn verify_handshake_response(
    response: &IpcMessage,
    expected_nonce: &[u8; CHALLENGE_NONCE_BYTES],
    expected_fortress_id: &str,
    pinned_public_key: &[u8],
) -> Result<HandshakeIdentity, AuthError> {
    let (fortress_id, signing_key_id, signature_b64url, peer_protocol_version, peer_capabilities) =
        match response {
            IpcMessage::HandshakeResponse {
                fortress_id,
                signing_key_id,
                nonce_signature_b64url,
                protocol_version,
                capabilities,
            } => (
                fortress_id.clone(),
                signing_key_id.clone(),
                nonce_signature_b64url.clone(),
                *protocol_version,
                capabilities.clone(),
            ),
            _ => return Err(AuthError::WrongMessageType),
        };

    if fortress_id != expected_fortress_id {
        return Err(AuthError::FortressIdMismatch {
            expected: expected_fortress_id.to_string(),
            got: fortress_id,
        });
    }

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

    let key = parse_strict_verifying_key(pinned_public_key)
        .map_err(|err| AuthError::PinnedKeyMalformed(err.to_string()))?;

    let signing_bytes = handshake_signing_bytes(
        expected_nonce,
        &fortress_id,
        &signing_key_id,
        peer_protocol_version,
        &peer_capabilities,
    );
    key.verify_strict(&signing_bytes, &signature)
        .map_err(|_| AuthError::SignatureMismatch)?;

    Ok(HandshakeIdentity {
        fortress_id,
        signing_key_id,
        peer_protocol_version,
        peer_capabilities,
    })
}

/// Look up the connecting peer's UID via SO_PEERCRED on Linux. On other
/// platforms this returns an error; production deployment is Linux only,
/// but unit tests on macOS use the `expect_uid: None` path which skips this
/// check.
#[cfg(target_os = "linux")]
pub fn peer_uid_for_stream(stream: &std::os::unix::net::UnixStream) -> Result<u32, AuthError> {
    use nix::sys::socket::getsockopt;
    use nix::sys::socket::sockopt::PeerCredentials;
    use std::os::fd::{AsRawFd, BorrowedFd};
    let fd = stream.as_raw_fd();
    // SAFETY: the &UnixStream borrow keeps the fd alive for the duration
    // of this call; getsockopt reads SO_PEERCRED without retaining the fd.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let cred = getsockopt(&borrowed, PeerCredentials)
        .map_err(|err| AuthError::PeerCred(err.to_string()))?;
    Ok(cred.uid())
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn peer_uid_for_stream(stream: &std::os::unix::net::UnixStream) -> Result<u32, AuthError> {
    use std::os::fd::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: getpeereid only reads credentials associated with this borrowed,
    // live connected Unix socket and writes the two initialized outputs.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 {
        Ok(uid)
    } else {
        Err(AuthError::PeerCred(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
pub fn peer_uid_for_stream(_stream: &std::os::unix::net::UnixStream) -> Result<u32, AuthError> {
    Err(AuthError::PeerCred(
        "peer UID lookup is unsupported".to_string(),
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
    fn pinned_key_rejects_identity_and_noncanonical_points() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("weak.key");
        let mut identity = [0u8; PUBLIC_KEY_LENGTH];
        identity[0] = 1;
        fs::write(&path, identity).unwrap();
        assert!(matches!(
            load_pinned_public_key(&path),
            Err(AuthError::PinnedKeyMalformed(_))
        ));

        identity[31] = 0x80;
        fs::write(&path, identity).unwrap();
        assert!(matches!(
            load_pinned_public_key(&path),
            Err(AuthError::PinnedKeyMalformed(_))
        ));
    }

    #[test]
    fn handshake_rejects_constructive_identity_key_forgery() {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};

        let nonce = generate_challenge_nonce();
        let mut identity = [0u8; PUBLIC_KEY_LENGTH];
        identity[0] = 1;
        let scalar = Scalar::from(1u64);
        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature[..32].copy_from_slice(&ED25519_BASEPOINT_POINT.compress().to_bytes());
        signature[32..].copy_from_slice(&scalar.to_bytes());
        let response = IpcMessage::HandshakeResponse {
            fortress_id: "deadbeef".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature),
            protocol_version: None,
            capabilities: Vec::new(),
        };
        assert!(matches!(
            verify_handshake_response(&response, &nonce, "deadbeef", &identity),
            Err(AuthError::PinnedKeyMalformed(_))
        ));
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
        let signature = signing.sign(&handshake_signing_bytes(
            &nonce,
            "deadbeef",
            "v1",
            None,
            &[],
        ));
        let response = IpcMessage::HandshakeResponse {
            fortress_id: "deadbeef".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_bytes()),
            protocol_version: None,
            capabilities: Vec::new(),
        };
        let identity = verify_handshake_response(&response, &nonce, "deadbeef", &public).unwrap();
        assert_eq!(identity.fortress_id, "deadbeef");
    }

    #[test]
    fn legacy_raw_nonce_signature_is_rejected_by_the_context_bound_protocol() {
        let signing = SigningKey::generate(&mut OsRng);
        let public = signing.verifying_key().to_bytes();
        let nonce = generate_challenge_nonce();
        let signature = signing.sign(&nonce);
        let response = IpcMessage::HandshakeResponse {
            fortress_id: "deadbeef".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_bytes()),
            protocol_version: Some(crate::ipc::messages::IPC_PROTOCOL_VERSION),
            capabilities: crate::ipc::messages::CAPABILITIES
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        };

        assert!(matches!(
            verify_handshake_response(&response, &nonce, "deadbeef", &public),
            Err(AuthError::SignatureMismatch)
        ));
    }

    #[test]
    fn signature_against_other_key_rejected() {
        let signing = SigningKey::generate(&mut OsRng);
        let other_signing = SigningKey::generate(&mut OsRng);
        let pinned = signing.verifying_key().to_bytes();
        let nonce = generate_challenge_nonce();
        let signature = other_signing.sign(&handshake_signing_bytes(
            &nonce,
            "deadbeef",
            "v1",
            None,
            &[],
        ));
        let response = IpcMessage::HandshakeResponse {
            fortress_id: "deadbeef".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_bytes()),
            protocol_version: None,
            capabilities: Vec::new(),
        };
        let err = verify_handshake_response(&response, &nonce, "deadbeef", &pinned).unwrap_err();
        assert!(matches!(err, AuthError::SignatureMismatch));
    }

    #[test]
    fn signature_over_wrong_nonce_rejected() {
        let signing = SigningKey::generate(&mut OsRng);
        let pinned = signing.verifying_key().to_bytes();
        let issued = generate_challenge_nonce();
        let attacker_nonce = generate_challenge_nonce();
        let signature = signing.sign(&handshake_signing_bytes(
            &attacker_nonce,
            "deadbeef",
            "v1",
            None,
            &[],
        ));
        let response = IpcMessage::HandshakeResponse {
            fortress_id: "deadbeef".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_bytes()),
            protocol_version: None,
            capabilities: Vec::new(),
        };
        let err = verify_handshake_response(&response, &issued, "deadbeef", &pinned).unwrap_err();
        assert!(matches!(err, AuthError::SignatureMismatch));
    }

    #[test]
    fn signature_cannot_be_reused_with_mutated_context() {
        let signing = SigningKey::generate(&mut OsRng);
        let pinned = signing.verifying_key().to_bytes();
        let nonce = generate_challenge_nonce();
        let capabilities = vec!["audit_drain_ack_response".to_string()];
        let signature = signing.sign(&handshake_signing_bytes(
            &nonce,
            "deadbeef",
            "v1",
            Some(2),
            &capabilities,
        ));
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
        for response in [
            IpcMessage::HandshakeResponse {
                fortress_id: "deadbeef".to_string(),
                signing_key_id: "v2".to_string(),
                nonce_signature_b64url: encoded.clone(),
                protocol_version: Some(2),
                capabilities: capabilities.clone(),
            },
            IpcMessage::HandshakeResponse {
                fortress_id: "deadbeef".to_string(),
                signing_key_id: "v1".to_string(),
                nonce_signature_b64url: encoded.clone(),
                protocol_version: Some(3),
                capabilities: capabilities.clone(),
            },
            IpcMessage::HandshakeResponse {
                fortress_id: "deadbeef".to_string(),
                signing_key_id: "v1".to_string(),
                nonce_signature_b64url: encoded.clone(),
                protocol_version: Some(2),
                capabilities: Vec::new(),
            },
        ] {
            assert!(matches!(
                verify_handshake_response(&response, &nonce, "deadbeef", &pinned),
                Err(AuthError::SignatureMismatch)
            ));
        }
        let wrong_fortress = IpcMessage::HandshakeResponse {
            fortress_id: "feedface".to_string(),
            signing_key_id: "v1".to_string(),
            nonce_signature_b64url: encoded,
            protocol_version: Some(2),
            capabilities,
        };
        assert!(matches!(
            verify_handshake_response(&wrong_fortress, &nonce, "deadbeef", &pinned),
            Err(AuthError::FortressIdMismatch { .. })
        ));
    }

    #[test]
    fn wrong_message_type_rejected() {
        let signing = SigningKey::generate(&mut OsRng);
        let pinned = signing.verifying_key().to_bytes();
        let nonce = generate_challenge_nonce();
        let bogus = IpcMessage::HandshakeChallenge {
            nonce_b64url: encode_nonce_b64url(&nonce),
            protocol_version: None,
            capabilities: Vec::new(),
        };
        let err = verify_handshake_response(&bogus, &nonce, "deadbeef", &pinned).unwrap_err();
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
            protocol_version: None,
            capabilities: Vec::new(),
        };
        let err = verify_handshake_response(&response, &nonce, "deadbeef", &pinned).unwrap_err();
        assert!(matches!(err, AuthError::SignatureDecode(_)));
    }
}
