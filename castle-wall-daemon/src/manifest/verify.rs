//! Manifest signature + per-rule SHA-256 verification.
//!
//! Mirrors `server/src/castle-wall/allowlist/parse.ts` exactly. Pure
//! verification; no filesystem I/O. PR 2b's inotify watcher feeds bytes
//! into these functions.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::constants::{SCHEMA_VERSION_V1, SIGNATURE_SCHEME_V1};
use crate::manifest::canonical_json::{canonicalize_to_bytes, CanonicalJsonError};

/// One entry in a manifest's rules array.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestRuleEntry {
    pub rule_id: String,
    pub file: String,
    pub sha256: String,
}

/// Optional agent-origin metadata stamped by the Sanctuary manifest publisher.
/// Linux uid-mode manifests bind the wall to the confined agent's ruid; the
/// daemon uses that uid to emit the same `fortress/uid-N` protection subject the
/// server/macOS path already expects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentOrigin {
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_helper_signing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_helper_team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_runtime_port_range: Option<[u32; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_uid: Option<u32>,
    pub system_uid_allow_ceiling: u32,
}

/// Optional operator/system-essential baseline allowlist covered by the same
/// manifest signature as the allowlist rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorBaselineEssential {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_app_identifier: Option<String>,
}

/// Wrapper shape for the TS `OperatorBaseline`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorBaseline {
    pub essentials: Vec<OperatorBaselineEssential>,
}

/// Unsigned manifest. Canonical-JSON of this shape is the signing input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowlistManifest {
    pub schema_version: u32,
    pub fortress_id: String,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_origin: Option<AgentOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_baseline: Option<OperatorBaseline>,
    pub rules: Vec<ManifestRuleEntry>,
}

/// Ed25519 signature wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSignature {
    pub signature_scheme: String,
    pub signing_key_id: String,
    pub signature_b64url: String,
}

/// Manifest plus signature; this is the structure persisted on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedManifest {
    pub manifest: AllowlistManifest,
    pub signature: ManifestSignature,
}

/// Body of a pinned-key rotation envelope (the bytes that are signed by both
/// the old and the new key per scope-lock §4 OQ #1 option (a)).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationBody {
    pub schema_version: u32,
    pub fortress_id: String,
    pub issued_at: String,
    pub old_key_hex: String,
    pub new_key_hex: String,
}

/// Cross-signed rotation envelope. Both `old_key_signature_b64url` (proving
/// the old custodian authorized the rotation) and `new_key_signature_b64url`
/// (proving the new key holder accepted custody) verify against the same
/// canonical-JSON of `RotationBody`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossSignedRotation {
    pub body: RotationBody,
    pub old_key_signature_b64url: String,
    pub new_key_signature_b64url: String,
}

/// Result of verifying a cross-signed rotation envelope. On success the
/// daemon may persist `accepted_new_key` to its pinned-key file (subject to
/// operator-approval gating; see scope-lock §4 OQ #1 option (b), which lands
/// alongside the prompt path in Checkpoint 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationVerifyOutcome {
    Accepted { accepted_new_key: [u8; PUBLIC_KEY_LENGTH] },
    Rejected { reason: String },
}

/// Verification result returned by both signature and rule-bytes paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    Ok,
    Failed { reason: String, issues: Vec<String> },
}

/// Verify the Ed25519 signature on a SignedManifest against a pinned public
/// key (raw 32-byte Ed25519). Mirrors verifyManifestSignature in parse.ts.
pub fn verify_manifest_signature(
    signed: &SignedManifest,
    pinned_public_key: &[u8],
) -> VerifyResult {
    if signed.signature.signature_scheme != SIGNATURE_SCHEME_V1 {
        return VerifyResult::Failed {
            reason: format!(
                "unsupported signature_scheme: {}",
                signed.signature.signature_scheme
            ),
            issues: Vec::new(),
        };
    }
    if signed.manifest.schema_version != SCHEMA_VERSION_V1 {
        return VerifyResult::Failed {
            reason: format!(
                "unsupported manifest schema_version: {}",
                signed.manifest.schema_version
            ),
            issues: Vec::new(),
        };
    }
    if pinned_public_key.len() != PUBLIC_KEY_LENGTH {
        return VerifyResult::Failed {
            reason: format!(
                "pinned public key wrong length (expected {}, got {})",
                PUBLIC_KEY_LENGTH,
                pinned_public_key.len()
            ),
            issues: Vec::new(),
        };
    }

    let manifest_value = match serde_json::to_value(&signed.manifest) {
        Ok(v) => v,
        Err(err) => {
            return VerifyResult::Failed {
                reason: format!("manifest serialization failed: {}", err),
                issues: Vec::new(),
            }
        }
    };

    let canonical = match canonicalize_to_bytes(&manifest_value) {
        Ok(b) => b,
        Err(CanonicalJsonError::NonFiniteNumber) => {
            return VerifyResult::Failed {
                reason: "manifest contains non-finite number".to_string(),
                issues: Vec::new(),
            }
        }
        Err(err) => {
            return VerifyResult::Failed {
                reason: format!("manifest canonicalization failed: {:?}", err),
                issues: Vec::new(),
            }
        }
    };

    let signature_bytes = match base64_url_decode(&signed.signature.signature_b64url) {
        Ok(b) => b,
        Err(err) => {
            return VerifyResult::Failed {
                reason: format!("signature base64url decode failed: {}", err),
                issues: Vec::new(),
            }
        }
    };

    if signature_bytes.len() != SIGNATURE_LENGTH {
        return VerifyResult::Failed {
            reason: format!(
                "signature wrong length (expected {}, got {})",
                SIGNATURE_LENGTH,
                signature_bytes.len()
            ),
            issues: Vec::new(),
        };
    }
    let mut sig_array = [0u8; SIGNATURE_LENGTH];
    sig_array.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_array);

    let mut pk_array = [0u8; PUBLIC_KEY_LENGTH];
    pk_array.copy_from_slice(pinned_public_key);
    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(k) => k,
        Err(err) => {
            return VerifyResult::Failed {
                reason: format!("pinned public key invalid: {}", err),
                issues: Vec::new(),
            }
        }
    };

    match verifying_key.verify(&canonical, &signature) {
        Ok(()) => VerifyResult::Ok,
        Err(_) => VerifyResult::Failed {
            reason: "manifest signature does not verify against pinned key".to_string(),
            issues: Vec::new(),
        },
    }
}

/// Verify each rule file's SHA-256 matches the manifest's recorded digest.
/// Caller must have already verified the manifest signature.
pub fn verify_rule_digests(
    signed: &SignedManifest,
    rule_files: &HashMap<String, Vec<u8>>,
) -> VerifyResult {
    let mut issues = Vec::new();
    for entry in &signed.manifest.rules {
        let bytes = match rule_files.get(&entry.file) {
            Some(b) => b,
            None => {
                issues.push(format!("rule file missing on disk: {}", entry.file));
                continue;
            }
        };
        let digest = sha256_hex(bytes);
        if digest != entry.sha256.to_lowercase() {
            issues.push(format!(
                "rule file sha256 mismatch for {} (manifest says {}, found {})",
                entry.file, entry.sha256, digest
            ));
        }
    }
    if issues.is_empty() {
        VerifyResult::Ok
    } else {
        VerifyResult::Failed {
            reason: "rule validation failed".to_string(),
            issues,
        }
    }
}

/// Verify a cross-signed rotation envelope against the currently-pinned
/// fortress public key. Mirrors §4 OQ #1 option (a): the proposed new key is
/// only acceptable when the envelope carries a valid old-key signature
/// (proving the old custodian authorized the change) AND a valid new-key
/// signature (proving the new key holder is in possession). The caller is
/// responsible for the operator-approval gate before persisting the new
/// pinned key (option (b); lands with the prompt path in Checkpoint 3).
pub fn verify_cross_signed_rotation(
    rotation: &CrossSignedRotation,
    pinned_public_key: &[u8],
) -> RotationVerifyOutcome {
    if rotation.body.schema_version != SCHEMA_VERSION_V1 {
        return RotationVerifyOutcome::Rejected {
            reason: format!(
                "unsupported rotation schema_version: {}",
                rotation.body.schema_version
            ),
        };
    }
    if pinned_public_key.len() != PUBLIC_KEY_LENGTH {
        return RotationVerifyOutcome::Rejected {
            reason: format!(
                "pinned public key wrong length (expected {}, got {})",
                PUBLIC_KEY_LENGTH,
                pinned_public_key.len()
            ),
        };
    }

    let old_key_bytes = match hex::decode(&rotation.body.old_key_hex) {
        Ok(b) => b,
        Err(err) => {
            return RotationVerifyOutcome::Rejected {
                reason: format!("old_key_hex decode failed: {}", err),
            }
        }
    };
    if old_key_bytes != pinned_public_key {
        return RotationVerifyOutcome::Rejected {
            reason: "rotation envelope's old_key does not match currently pinned key".to_string(),
        };
    }

    let new_key_bytes = match hex::decode(&rotation.body.new_key_hex) {
        Ok(b) => b,
        Err(err) => {
            return RotationVerifyOutcome::Rejected {
                reason: format!("new_key_hex decode failed: {}", err),
            }
        }
    };
    if new_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return RotationVerifyOutcome::Rejected {
            reason: format!(
                "new_key_hex wrong length (expected {}, got {})",
                PUBLIC_KEY_LENGTH,
                new_key_bytes.len()
            ),
        };
    }
    if new_key_bytes == pinned_public_key {
        return RotationVerifyOutcome::Rejected {
            reason: "rotation envelope's new_key equals old_key; no-op rotation rejected"
                .to_string(),
        };
    }

    let canonical = match serde_json::to_value(&rotation.body)
        .map_err(|err| format!("rotation body serialize failed: {}", err))
        .and_then(|v| {
            canonicalize_to_bytes(&v).map_err(|err| format!("canonicalize failed: {:?}", err))
        }) {
        Ok(b) => b,
        Err(reason) => return RotationVerifyOutcome::Rejected { reason },
    };

    let old_sig = match decode_signature(&rotation.old_key_signature_b64url) {
        Ok(b) => b,
        Err(reason) => return RotationVerifyOutcome::Rejected { reason },
    };
    let new_sig = match decode_signature(&rotation.new_key_signature_b64url) {
        Ok(b) => b,
        Err(reason) => return RotationVerifyOutcome::Rejected { reason },
    };

    let mut old_key_arr = [0u8; PUBLIC_KEY_LENGTH];
    old_key_arr.copy_from_slice(pinned_public_key);
    let old_verifying_key = match VerifyingKey::from_bytes(&old_key_arr) {
        Ok(k) => k,
        Err(err) => {
            return RotationVerifyOutcome::Rejected {
                reason: format!("pinned public key invalid: {}", err),
            }
        }
    };
    let mut new_key_arr = [0u8; PUBLIC_KEY_LENGTH];
    new_key_arr.copy_from_slice(&new_key_bytes);
    let new_verifying_key = match VerifyingKey::from_bytes(&new_key_arr) {
        Ok(k) => k,
        Err(err) => {
            return RotationVerifyOutcome::Rejected {
                reason: format!("rotation new_key invalid: {}", err),
            }
        }
    };

    if old_verifying_key.verify(&canonical, &old_sig).is_err() {
        return RotationVerifyOutcome::Rejected {
            reason: "rotation envelope's old_key_signature does not verify".to_string(),
        };
    }
    if new_verifying_key.verify(&canonical, &new_sig).is_err() {
        return RotationVerifyOutcome::Rejected {
            reason: "rotation envelope's new_key_signature does not verify".to_string(),
        };
    }

    RotationVerifyOutcome::Accepted {
        accepted_new_key: new_key_arr,
    }
}

fn decode_signature(b64url: &str) -> Result<Signature, String> {
    let bytes = base64_url_decode(b64url).map_err(|err| format!("signature decode: {}", err))?;
    if bytes.len() != SIGNATURE_LENGTH {
        return Err(format!(
            "signature wrong length (expected {}, got {})",
            SIGNATURE_LENGTH,
            bytes.len()
        ));
    }
    let mut arr = [0u8; SIGNATURE_LENGTH];
    arr.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(&arr))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out.iter() {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn build_signed_manifest() -> (SignedManifest, [u8; PUBLIC_KEY_LENGTH]) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let manifest = AllowlistManifest {
            schema_version: SCHEMA_VERSION_V1,
            fortress_id: "deadbeef".to_string(),
            issued_at: "2026-05-04T00:00:00Z".to_string(),
            agent_origin: None,
            operator_baseline: None,
            rules: vec![ManifestRuleEntry {
                rule_id: "uuid-1".to_string(),
                file: "rule-1.json".to_string(),
                sha256: "00".to_string(),
            }],
        };
        let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let signature = signing_key.sign(&canonical);
        let signature_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signature.to_bytes());
        let signed = SignedManifest {
            manifest,
            signature: ManifestSignature {
                signature_scheme: SIGNATURE_SCHEME_V1.to_string(),
                signing_key_id: "test-key".to_string(),
                signature_b64url,
            },
        };
        (signed, verifying_key.to_bytes())
    }

    #[test]
    fn happy_path_verifies() {
        let (signed, pk) = build_signed_manifest();
        assert_eq!(verify_manifest_signature(&signed, &pk), VerifyResult::Ok);
    }

    #[test]
    fn unknown_signature_scheme_rejected() {
        let (mut signed, pk) = build_signed_manifest();
        signed.signature.signature_scheme = "alien-v1".to_string();
        match verify_manifest_signature(&signed, &pk) {
            VerifyResult::Failed { reason, .. } => assert!(reason.contains("signature_scheme")),
            _ => panic!("expected failure"),
        }
    }

    #[test]
    fn unknown_schema_version_rejected() {
        let (mut signed, pk) = build_signed_manifest();
        signed.manifest.schema_version = 99;
        match verify_manifest_signature(&signed, &pk) {
            VerifyResult::Failed { reason, .. } => assert!(reason.contains("schema_version")),
            _ => panic!("expected failure"),
        }
    }

    #[test]
    fn mismatched_pinned_key_rejected() {
        let (signed, _pk) = build_signed_manifest();
        let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        match verify_manifest_signature(&signed, &other) {
            VerifyResult::Failed { reason, .. } => assert!(reason.contains("does not verify")),
            _ => panic!("expected failure"),
        }
    }

    #[test]
    fn rule_digest_check_passes_when_bytes_match() {
        let (mut signed, _pk) = build_signed_manifest();
        let rule_bytes = b"{\"id\":\"uuid-1\"}".to_vec();
        signed.manifest.rules[0].sha256 = sha256_hex(&rule_bytes);
        let mut files = HashMap::new();
        files.insert("rule-1.json".to_string(), rule_bytes);
        assert_eq!(verify_rule_digests(&signed, &files), VerifyResult::Ok);
    }

    #[test]
    fn rule_digest_check_flags_missing_file() {
        let (signed, _pk) = build_signed_manifest();
        let files = HashMap::new();
        match verify_rule_digests(&signed, &files) {
            VerifyResult::Failed { issues, .. } => {
                assert!(issues.iter().any(|i| i.contains("missing on disk")));
            }
            _ => panic!("expected failure"),
        }
    }

    fn build_cross_signed_rotation(
        old_signing: &SigningKey,
        new_signing: &SigningKey,
    ) -> CrossSignedRotation {
        let body = RotationBody {
            schema_version: SCHEMA_VERSION_V1,
            fortress_id: "deadbeef".to_string(),
            issued_at: "2026-05-05T00:00:00Z".to_string(),
            old_key_hex: hex::encode(old_signing.verifying_key().to_bytes()),
            new_key_hex: hex::encode(new_signing.verifying_key().to_bytes()),
        };
        let canonical = canonicalize_to_bytes(&serde_json::to_value(&body).unwrap()).unwrap();
        let old_sig = old_signing.sign(&canonical);
        let new_sig = new_signing.sign(&canonical);
        CrossSignedRotation {
            body,
            old_key_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(old_sig.to_bytes()),
            new_key_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(new_sig.to_bytes()),
        }
    }

    #[test]
    fn cross_signed_rotation_happy_path() {
        let old = SigningKey::generate(&mut OsRng);
        let new = SigningKey::generate(&mut OsRng);
        let rotation = build_cross_signed_rotation(&old, &new);
        let outcome = verify_cross_signed_rotation(&rotation, &old.verifying_key().to_bytes());
        match outcome {
            RotationVerifyOutcome::Accepted { accepted_new_key } => {
                assert_eq!(accepted_new_key, new.verifying_key().to_bytes());
            }
            RotationVerifyOutcome::Rejected { reason } => panic!("rejected: {}", reason),
        }
    }

    #[test]
    fn rotation_rejected_when_old_key_does_not_match_pinned() {
        let old = SigningKey::generate(&mut OsRng);
        let new = SigningKey::generate(&mut OsRng);
        let rotation = build_cross_signed_rotation(&old, &new);
        let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        match verify_cross_signed_rotation(&rotation, &other) {
            RotationVerifyOutcome::Rejected { reason } => {
                assert!(reason.contains("does not match currently pinned"));
            }
            RotationVerifyOutcome::Accepted { .. } => panic!("expected rejection"),
        }
    }

    #[test]
    fn rotation_rejected_when_new_key_signature_invalid() {
        let old = SigningKey::generate(&mut OsRng);
        let new = SigningKey::generate(&mut OsRng);
        let mut rotation = build_cross_signed_rotation(&old, &new);
        // Corrupt the new-key signature by swapping in one over a different message.
        let bogus = old.sign(b"different bytes");
        rotation.new_key_signature_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(bogus.to_bytes());
        match verify_cross_signed_rotation(&rotation, &old.verifying_key().to_bytes()) {
            RotationVerifyOutcome::Rejected { reason } => {
                assert!(reason.contains("new_key_signature does not verify"));
            }
            RotationVerifyOutcome::Accepted { .. } => panic!("expected rejection"),
        }
    }

    #[test]
    fn rotation_rejected_when_old_key_signature_invalid() {
        let old = SigningKey::generate(&mut OsRng);
        let new = SigningKey::generate(&mut OsRng);
        let mut rotation = build_cross_signed_rotation(&old, &new);
        // Corrupt the old-key signature.
        let bogus = new.sign(b"different bytes");
        rotation.old_key_signature_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(bogus.to_bytes());
        match verify_cross_signed_rotation(&rotation, &old.verifying_key().to_bytes()) {
            RotationVerifyOutcome::Rejected { reason } => {
                assert!(reason.contains("old_key_signature does not verify"));
            }
            RotationVerifyOutcome::Accepted { .. } => panic!("expected rejection"),
        }
    }

    #[test]
    fn rotation_rejected_when_new_key_equals_old() {
        let old = SigningKey::generate(&mut OsRng);
        let rotation = build_cross_signed_rotation(&old, &old);
        match verify_cross_signed_rotation(&rotation, &old.verifying_key().to_bytes()) {
            RotationVerifyOutcome::Rejected { reason } => {
                assert!(reason.contains("no-op rotation"));
            }
            RotationVerifyOutcome::Accepted { .. } => panic!("expected rejection"),
        }
    }
}
