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

/// Unsigned manifest. Canonical-JSON of this shape is the signing input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowlistManifest {
    pub schema_version: u32,
    pub fortress_id: String,
    pub issued_at: String,
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
}
