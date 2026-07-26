//! Manifest store: orchestrates pinned-key load, manifest read-from-disk,
//! signature verification, per-rule SHA-256 verification, and the prior-good
//! snapshot that powers the F-2 (manifest-signature-failure) disposition.
//!
//! Per scope-lock §4 the policy on disk is one signed `manifest.json` plus a
//! directory of one-rule-per-file JSON documents under `<policy_dir>/rules/`.
//! On every reload the store: parses manifest.json, verifies its Ed25519
//! signature against the TOFU-pinned fortress public key, reads each
//! referenced rule file, verifies SHA-256 digests, and atomically swaps the
//! in-memory `current` snapshot only on full success. On any verification
//! failure the prior `current` snapshot is retained (F-2: refuse the reload,
//! keep prior policy in force).
//!
//! The store does NOT do filesystem watching; that is `manifest::watcher`.
//! The store does NOT call out to IPC; the IPC dispatch in `ipc::server`
//! invokes `reload()` and translates the result into a PolicyReloadResponse.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::constants::SCHEMA_VERSION_V1;
use crate::manifest::verify::{
    verify_manifest_signature, verify_rule_digests, AllowlistManifest, ManifestSignature,
    SignedManifest, VerifyResult,
};
use crate::policy::{PolicySnapshot, PolicySnapshotError};

/// File name of the canonical signed manifest within the policy directory.
pub const MANIFEST_FILENAME: &str = "manifest.json";

/// Subdirectory of the policy directory holding the rule files.
pub const RULES_SUBDIR: &str = "rules";

/// The currently-loaded, fully-verified manifest plus the rule bytes it
/// references. Returned to the IPC dispatch on a successful reload, exposed
/// via `current()` for status reads.
#[derive(Debug, Clone)]
pub struct LoadedManifest {
    pub signed: SignedManifest,
    pub rule_files: HashMap<String, Vec<u8>>,
    pub manifest_signature_b64url: String,
    pub rule_count: u32,
}

/// Errors emitted by the manifest store. All of these are F-2 (mid-session)
/// or F-4 (startup) candidates; the IPC dispatch decides which based on
/// whether the daemon is in boot or in steady state.
#[derive(Debug, thiserror::Error, Clone)]
pub enum ManifestStoreError {
    #[error("pinned-key file missing or unreadable at {path}: {source_message}")]
    PinnedKeyIo {
        path: PathBuf,
        source_message: String,
    },
    #[error("pinned-key file at {path} has wrong length: expected 32, got {actual}")]
    PinnedKeyLength { path: PathBuf, actual: usize },
    #[error("manifest file missing or unreadable at {path}: {source_message}")]
    ManifestIo {
        path: PathBuf,
        source_message: String,
    },
    #[error("manifest at {path} failed JSON parse: {source_message}")]
    ManifestParse {
        path: PathBuf,
        source_message: String,
    },
    #[error("manifest signature verification failed: {reason}")]
    ManifestSignatureFailed { reason: String },
    #[error("manifest schema_version {found} unsupported (expected {expected})")]
    ManifestSchemaUnsupported { found: u32, expected: u32 },
    #[error("rule file read failed for {file}: {source_message}")]
    RuleFileIo {
        file: String,
        source_message: String,
    },
    #[error("rule digest verification failed: {reason}; issues={issues:?}")]
    RuleDigestFailed {
        reason: String,
        issues: Vec<String>,
    },
    #[error("policy snapshot construction failed: {source_message}")]
    PolicySnapshot { source_message: String },
}

impl From<PolicySnapshotError> for ManifestStoreError {
    fn from(err: PolicySnapshotError) -> Self {
        ManifestStoreError::PolicySnapshot {
            source_message: err.to_string(),
        }
    }
}

/// In-memory manifest store. Holds the TOFU-pinned key and the last
/// successfully-verified `LoadedManifest` snapshot (if any), plus a
/// derived [`PolicySnapshot`] that the policy evaluator runs against on
/// every outbound attempt.
#[derive(Debug)]
pub struct ManifestStore {
    policy_dir: PathBuf,
    pinned_key_path: PathBuf,
    pinned_key: [u8; 32],
    current: Option<LoadedManifest>,
    current_snapshot: Option<PolicySnapshot>,
}

impl ManifestStore {
    /// Construct a store with the pinned key already loaded. Used by the
    /// daemon at boot, where pinned-key load is a refuse-to-start gate.
    pub fn new(policy_dir: PathBuf, pinned_key_path: PathBuf, pinned_key: [u8; 32]) -> Self {
        Self {
            policy_dir,
            pinned_key_path,
            pinned_key,
            current: None,
            current_snapshot: None,
        }
    }

    /// Read the pinned-key file from disk and return the raw 32-byte
    /// verifying key. Used by callers that want to refuse-to-start when the
    /// pin file is missing or malformed.
    pub fn load_pinned_key(path: &Path) -> Result<[u8; 32], ManifestStoreError> {
        let bytes = fs::read(path).map_err(|err| ManifestStoreError::PinnedKeyIo {
            path: path.to_path_buf(),
            source_message: err.to_string(),
        })?;
        if bytes.len() != 32 {
            return Err(ManifestStoreError::PinnedKeyLength {
                path: path.to_path_buf(),
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Atomically replace the pinned-key file on disk with `new_key`. Used
    /// after a cross-signed rotation envelope has verified AND received
    /// operator approval (operator-approval gating lands in Checkpoint 3).
    pub fn persist_new_pinned_key(&mut self, new_key: [u8; 32]) -> Result<(), ManifestStoreError> {
        let tmp = self.pinned_key_path.with_extension("tmp");
        let mut f = fs::File::create(&tmp).map_err(|err| ManifestStoreError::PinnedKeyIo {
            path: tmp.clone(),
            source_message: err.to_string(),
        })?;
        f.write_all(&new_key)
            .map_err(|err| ManifestStoreError::PinnedKeyIo {
                path: tmp.clone(),
                source_message: err.to_string(),
            })?;
        f.sync_all()
            .map_err(|err| ManifestStoreError::PinnedKeyIo {
                path: tmp.clone(),
                source_message: err.to_string(),
            })?;
        drop(f);
        fs::rename(&tmp, &self.pinned_key_path).map_err(|err| {
            ManifestStoreError::PinnedKeyIo {
                path: self.pinned_key_path.clone(),
                source_message: err.to_string(),
            }
        })?;
        self.pinned_key = new_key;
        Ok(())
    }

    pub fn pinned_key(&self) -> &[u8; 32] {
        &self.pinned_key
    }

    pub fn current(&self) -> Option<&LoadedManifest> {
        self.current.as_ref()
    }

    /// Borrow the current [`PolicySnapshot`] derived from the last
    /// successful reload. None until the first successful reload.
    pub fn current_snapshot(&self) -> Option<&PolicySnapshot> {
        self.current_snapshot.as_ref()
    }

    /// Try to reload the manifest from disk and rebuild the derived
    /// [`PolicySnapshot`]. On success returns a reference to the new
    /// current `LoadedManifest`. On any failure (signature verify, rule
    /// digest, snapshot construction) the `current` and `current_snapshot`
    /// fields are left untouched (F-2 disposition: keep prior good policy
    /// in force) and the caller surfaces the error to Sanctuary main as a
    /// `PolicyReloadResponse` with `ok: false`.
    pub fn reload(&mut self) -> Result<&LoadedManifest, ManifestStoreError> {
        let next = load_signed_manifest_from_disk(&self.policy_dir, &self.pinned_key)?;
        // Build the snapshot before mutating self so a parse / id-mismatch
        // failure on the rule bodies preserves the prior good snapshot.
        let snapshot = PolicySnapshot::from_loaded_manifest(&next)?;
        self.current = Some(next);
        self.current_snapshot = Some(snapshot);
        // Safety: `self.current = Some(next)` two lines above sets the option;
        // there is no intervening mutation point on this single-threaded path,
        // so the option is guaranteed to be Some at the read below.
        Ok(self.current.as_ref().expect("current set above"))
    }
}

/// Read + parse + verify a SignedManifest from `<policy_dir>/manifest.json`,
/// then read + SHA-256-verify every referenced rule file from
/// `<policy_dir>/rules/<file>`. Returns a `LoadedManifest` snapshot on full
/// success; any failure aborts before mutating any caller state.
pub fn load_signed_manifest_from_disk(
    policy_dir: &Path,
    pinned_key: &[u8; 32],
) -> Result<LoadedManifest, ManifestStoreError> {
    let manifest_path = policy_dir.join(MANIFEST_FILENAME);
    let raw =
        fs::read_to_string(&manifest_path).map_err(|err| ManifestStoreError::ManifestIo {
            path: manifest_path.clone(),
            source_message: err.to_string(),
        })?;

    // Parse the manifest envelope (manifest body + signature wrapper).
    let parsed: ParsedSignedManifest = serde_json::from_str(&raw).map_err(|err| {
        ManifestStoreError::ManifestParse {
            path: manifest_path.clone(),
            source_message: err.to_string(),
        }
    })?;

    let signed = SignedManifest {
        manifest: parsed.manifest,
        signature: parsed.signature,
    };

    if signed.manifest.schema_version != SCHEMA_VERSION_V1 {
        return Err(ManifestStoreError::ManifestSchemaUnsupported {
            found: signed.manifest.schema_version,
            expected: SCHEMA_VERSION_V1,
        });
    }

    match verify_manifest_signature(&signed, pinned_key) {
        VerifyResult::Ok => {}
        VerifyResult::Failed { reason, .. } => {
            return Err(ManifestStoreError::ManifestSignatureFailed { reason });
        }
    }

    let rules_dir = policy_dir.join(RULES_SUBDIR);
    let mut rule_files: HashMap<String, Vec<u8>> = HashMap::new();
    for entry in &signed.manifest.rules {
        let path = rules_dir.join(&entry.file);
        let bytes = fs::read(&path).map_err(|err| ManifestStoreError::RuleFileIo {
            file: entry.file.clone(),
            source_message: err.to_string(),
        })?;
        rule_files.insert(entry.file.clone(), bytes);
    }

    match verify_rule_digests(&signed, &rule_files) {
        VerifyResult::Ok => {}
        VerifyResult::Failed { reason, issues } => {
            return Err(ManifestStoreError::RuleDigestFailed { reason, issues });
        }
    }

    let rule_count = signed.manifest.rules.len() as u32;
    let manifest_signature_b64url = signed.signature.signature_b64url.clone();

    Ok(LoadedManifest {
        signed,
        rule_files,
        manifest_signature_b64url,
        rule_count,
    })
}

/// Mirrors the on-disk signed manifest envelope shape so serde_json can
/// deserialize without forcing the public `SignedManifest` to derive
/// `Default`. Kept private; callers see `SignedManifest` only.
#[derive(serde::Serialize, serde::Deserialize)]
struct ParsedSignedManifest {
    manifest: AllowlistManifest,
    signature: ManifestSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::canonical_json::canonicalize_to_bytes;
    use crate::manifest::verify::ManifestRuleEntry;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use std::fs;
    use tempfile::TempDir;

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

    struct WrittenPolicy {
        dir: TempDir,
        pinned_key: [u8; 32],
        signing_key: SigningKey,
    }

    /// Build a minimally-valid `AllowlistRule` JSON body whose `id` field
    /// matches the manifest entry's `rule_id`. The store tests historically
    /// used opaque blobs like `{"a":1}` because the loader did not parse
    /// rule bodies; PolicySnapshot construction now does, so the bodies
    /// must round-trip through `AllowlistRule`.
    fn rule_body_for(rule_id: &str) -> Vec<u8> {
        let body = format!(
            "{{\"id\":\"{rule_id}\",\"schema_version\":1,\"created_at\":\"2026-05-05T00:00:00Z\",\"match\":{{}},\"disposition\":\"allow\"}}"
        );
        body.into_bytes()
    }

    /// Write a signed-manifest policy directory with `count` minimally-valid
    /// rule bodies under `<dir>/rules/rule-N.json`. Returns the directory
    /// handle, the pinned key the manifest was signed under, and the
    /// signing key for tests that re-sign. Tests that want to exercise
    /// failure paths corrupt the on-disk artifacts after this returns.
    fn write_valid_policy(count: usize) -> WrittenPolicy {
        let signing = SigningKey::generate(&mut OsRng);
        let pinned_key = signing.verifying_key().to_bytes();
        let dir = TempDir::new().unwrap();
        let policy_dir = dir.path();
        fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();

        let mut entries = Vec::new();
        for i in 0..count {
            let file = format!("rule-{}.json", i);
            let rule_id = format!("uuid-{}", i);
            let body = rule_body_for(&rule_id);
            fs::write(policy_dir.join(RULES_SUBDIR).join(&file), &body).unwrap();
            entries.push(ManifestRuleEntry {
                rule_id,
                file,
                sha256: sha256_hex(&body),
            });
        }
        // Every composed manifest must carry the genuine habeas local lane
        // (always-on-lane gate, codex round-4 HIGH); the snapshot the store
        // builds on reload refuses a lane-less manifest.
        let habeas_body = crate::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes().to_vec();
        let habeas_file = "rule-habeas.json".to_string();
        fs::write(
            policy_dir.join(RULES_SUBDIR).join(&habeas_file),
            &habeas_body,
        )
        .unwrap();
        entries.push(ManifestRuleEntry {
            rule_id: crate::habeas::HABEAS_LOCAL_RULE_ID.to_string(),
            file: habeas_file,
            sha256: sha256_hex(&habeas_body),
        });

        let manifest = AllowlistManifest {
            schema_version: SCHEMA_VERSION_V1,
            fortress_id: "deadbeef".to_string(),
            issued_at: "2026-05-05T00:00:00Z".to_string(),
            agent_origin: None,
            operator_baseline: None,
            rules: entries,
        };
        let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let sig = signing.sign(&canonical);
        let signature_b64url =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let signed = SignedManifest {
            manifest,
            signature: ManifestSignature {
                signature_scheme: crate::constants::SIGNATURE_SCHEME_V1.to_string(),
                signing_key_id: "test".to_string(),
                signature_b64url,
            },
        };
        let envelope = ParsedSignedManifest {
            manifest: signed.manifest,
            signature: signed.signature,
        };
        let serialized = serde_json::to_string_pretty(&envelope).unwrap();
        fs::write(policy_dir.join(MANIFEST_FILENAME), serialized).unwrap();
        WrittenPolicy {
            dir,
            pinned_key,
            signing_key: signing,
        }
    }

    #[test]
    fn load_signed_manifest_happy_path() {
        let policy = write_valid_policy(2);
        let loaded = load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key)
            .expect("load");
        // 2 synthetic rules + the always-present habeas local lane.
        assert_eq!(loaded.rule_count, 3);
        assert_eq!(loaded.rule_files.len(), 3);
        assert!(loaded.rule_files.contains_key("rule-0.json"));
    }

    #[test]
    fn load_fails_when_manifest_signature_does_not_verify() {
        let policy = write_valid_policy(1);
        // Replace the pinned key with a different one so the existing
        // signature cannot verify against it.
        let attacker = SigningKey::generate(&mut OsRng);
        let bad_pin = attacker.verifying_key().to_bytes();
        let err = load_signed_manifest_from_disk(policy.dir.path(), &bad_pin).unwrap_err();
        assert!(matches!(err, ManifestStoreError::ManifestSignatureFailed { .. }));
    }

    #[test]
    fn load_fails_when_rule_file_missing() {
        let policy = write_valid_policy(1);
        // Remove the rule file referenced by the manifest.
        fs::remove_file(policy.dir.path().join(RULES_SUBDIR).join("rule-0.json")).unwrap();
        let err = load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
        assert!(matches!(err, ManifestStoreError::RuleFileIo { .. }));
    }

    #[test]
    fn load_fails_when_rule_file_tampered() {
        let policy = write_valid_policy(1);
        // Swap the rule file body without updating the manifest digest.
        fs::write(
            policy.dir.path().join(RULES_SUBDIR).join("rule-0.json"),
            b"{\"a\":2}",
        )
        .unwrap();
        let err = load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
        assert!(matches!(err, ManifestStoreError::RuleDigestFailed { .. }));
    }

    #[test]
    fn load_fails_when_manifest_missing() {
        let policy = write_valid_policy(1);
        fs::remove_file(policy.dir.path().join(MANIFEST_FILENAME)).unwrap();
        let err = load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
        assert!(matches!(err, ManifestStoreError::ManifestIo { .. }));
    }

    #[test]
    fn load_fails_when_schema_version_unknown() {
        let policy = write_valid_policy(1);
        // Rewrite the manifest with an unsupported schema_version. The
        // signature will then fail too, but schema_version is checked first.
        let raw = fs::read_to_string(policy.dir.path().join(MANIFEST_FILENAME)).unwrap();
        let bumped = raw.replace("\"schema_version\": 1", "\"schema_version\": 99");
        fs::write(policy.dir.path().join(MANIFEST_FILENAME), bumped).unwrap();
        let err = load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
        assert!(matches!(err, ManifestStoreError::ManifestSchemaUnsupported { .. }));
    }

    #[test]
    fn store_reload_updates_current_on_success() {
        let policy = write_valid_policy(1);
        let pinned_path = policy.dir.path().join("pinned.key");
        fs::write(&pinned_path, policy.pinned_key).unwrap();
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            pinned_path,
            policy.pinned_key,
        );
        assert!(store.current().is_none());
        let loaded = store.reload().expect("reload");
        // 1 synthetic rule + the habeas local lane.
        assert_eq!(loaded.rule_count, 2);
        assert!(store.current().is_some());
    }

    #[test]
    fn store_reload_builds_policy_snapshot() {
        let policy = write_valid_policy(2);
        let pinned_path = policy.dir.path().join("pinned.key");
        fs::write(&pinned_path, policy.pinned_key).unwrap();
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            pinned_path,
            policy.pinned_key,
        );
        assert!(store.current_snapshot().is_none());
        store.reload().expect("reload");
        let snap = store.current_snapshot().expect("snapshot");
        // 2 synthetic rules + the habeas local lane.
        assert_eq!(snap.rules.len(), 3);
        assert_eq!(snap.fortress_id, "deadbeef");
        // Rule ids derived from rule_body_for("uuid-N"), then the lane.
        assert_eq!(snap.rules[0].id, "uuid-0");
        assert_eq!(snap.rules[1].id, "uuid-1");
        assert_eq!(snap.rules[2].id, crate::habeas::HABEAS_LOCAL_RULE_ID);
    }

    #[test]
    fn store_reload_keeps_prior_snapshot_on_rule_parse_failure() {
        // Tighter F-2 invariant: even when the rule digest matches but the
        // rule body fails to round-trip through AllowlistRule, the prior
        // snapshot is retained.
        let policy = write_valid_policy(1);
        let pinned_path = policy.dir.path().join("pinned.key");
        fs::write(&pinned_path, policy.pinned_key).unwrap();
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            pinned_path,
            policy.pinned_key,
        );
        store.reload().expect("first reload");
        let prior_snapshot_rule_count = store.current_snapshot().unwrap().rules.len();

        // Re-write the rule body to something whose SHA-256 still matches
        // the manifest entry but does NOT parse as AllowlistRule. We do this
        // by re-signing the manifest with a body that has the digest the
        // manifest entry expects. The simpler equivalent: rewrite the rule
        // body AND the manifest digest to keep the digest aligned but the
        // body invalid as AllowlistRule.
        let rule_path = policy.dir.path().join(RULES_SUBDIR).join("rule-0.json");
        let bad_body = b"{\"id\":\"uuid-0\",\"schema_version\":1}";
        // Can't simply overwrite, the digest in the existing manifest no
        // longer matches. The real demonstration here is via the snapshot
        // construction error class. Use the lower-level constructor to
        // exercise it.
        fs::write(&rule_path, bad_body).unwrap();
        // Bump the manifest's digest entry to match this body so the
        // digest gate doesn't trip first; the snapshot construction is the
        // gate we want to exercise.
        let raw =
            fs::read_to_string(policy.dir.path().join(MANIFEST_FILENAME)).unwrap();
        // Compute the new digest and resign the manifest.
        use base64::Engine;
        use ed25519_dalek::Signer;
        let new_digest = sha256_hex(bad_body);
        // Parse the existing signed manifest, swap the digest, re-canonicalize, re-sign.
        let parsed: super::ParsedSignedManifest = serde_json::from_str(&raw).unwrap();
        let mut new_manifest = parsed.manifest.clone();
        if let Some(entry) = new_manifest.rules.first_mut() {
            entry.sha256 = new_digest;
        }
        let canonical = canonicalize_to_bytes(&serde_json::to_value(&new_manifest).unwrap()).unwrap();
        let new_sig = policy.signing_key.sign(&canonical);
        let new_sig_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(new_sig.to_bytes());
        let new_envelope = SignedManifest {
            manifest: new_manifest,
            signature: ManifestSignature {
                signature_scheme: crate::constants::SIGNATURE_SCHEME_V1.to_string(),
                signing_key_id: "test".to_string(),
                signature_b64url: new_sig_b64,
            },
        };
        let serialized = serde_json::to_string_pretty(&super::ParsedSignedManifest {
            manifest: new_envelope.manifest,
            signature: new_envelope.signature,
        })
        .unwrap();
        fs::write(policy.dir.path().join(MANIFEST_FILENAME), serialized).unwrap();

        // Now the manifest signature + digest are clean, but the rule body
        // is missing required AllowlistRule fields (no `match`, no
        // `disposition`). The reload should fail at snapshot construction;
        // the prior snapshot must remain in force.
        let err = store.reload().unwrap_err();
        assert!(matches!(err, ManifestStoreError::PolicySnapshot { .. }));
        let kept = store.current_snapshot().expect("prior snapshot retained");
        assert_eq!(kept.rules.len(), prior_snapshot_rule_count);
    }

    #[test]
    fn store_reload_keeps_prior_on_failure() {
        // F-2 disposition: a failed reload leaves `current` unchanged.
        let policy = write_valid_policy(1);
        let pinned_path = policy.dir.path().join("pinned.key");
        fs::write(&pinned_path, policy.pinned_key).unwrap();
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            pinned_path,
            policy.pinned_key,
        );
        store.reload().expect("first reload");
        let prior_signature = store.current().unwrap().manifest_signature_b64url.clone();

        // Tamper with the rule file. Reload should fail; current should
        // still hold the prior good snapshot.
        fs::write(
            policy.dir.path().join(RULES_SUBDIR).join("rule-0.json"),
            b"{\"a\":2}",
        )
        .unwrap();
        let err = store.reload().unwrap_err();
        assert!(matches!(err, ManifestStoreError::RuleDigestFailed { .. }));
        assert!(store.current().is_some());
        assert_eq!(
            store.current().unwrap().manifest_signature_b64url,
            prior_signature
        );
    }

    #[test]
    fn persist_new_pinned_key_atomically_replaces_pin_file() {
        let policy = write_valid_policy(1);
        let pinned_path = policy.dir.path().join("pinned.key");
        fs::write(&pinned_path, policy.pinned_key).unwrap();
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            pinned_path.clone(),
            policy.pinned_key,
        );
        let new = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        store.persist_new_pinned_key(new).expect("persist");
        let on_disk = fs::read(&pinned_path).unwrap();
        assert_eq!(on_disk.as_slice(), &new);
        assert_eq!(*store.pinned_key(), new);
    }

    #[test]
    fn load_pinned_key_rejects_wrong_length() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pinned.key");
        fs::write(&path, b"short").unwrap();
        let err = ManifestStore::load_pinned_key(&path).unwrap_err();
        assert!(matches!(err, ManifestStoreError::PinnedKeyLength { .. }));
    }

    // Suppress unused-field warnings on WrittenPolicy.signing_key in tests
    // that don't need to re-sign.
    #[allow(dead_code)]
    fn _signing_key_field_used(p: &WrittenPolicy) -> &SigningKey {
        &p.signing_key
    }
}
