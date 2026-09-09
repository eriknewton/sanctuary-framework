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
//! Production callers can mutate the live snapshot only through
//! `reload_with_authorization`, which owns prepare -> required authorization ->
//! exact commit. The raw prepare/commit operations are private so no sibling
//! module can accidentally publish an unaudited generation.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};

use crate::constants::SCHEMA_VERSION_V1;
use crate::crypto::parse_strict_verifying_key;
use crate::manifest::rule_identity::preflight_manifest_rule_entries;
use crate::manifest::verify::{
    verify_manifest_signature, verify_rule_digests, AllowlistManifest, ManifestSignature,
    SignedManifest, VerifyResult,
};
use crate::policy::{PolicySnapshot, PolicySnapshotError};

/// File name of the canonical signed manifest within the policy directory.
pub const MANIFEST_FILENAME: &str = "manifest.json";

/// Subdirectory of the policy directory holding the rule files.
pub const RULES_SUBDIR: &str = "rules";
const MANIFEST_HIGH_WATER_FILENAME: &str = ".manifest-high-water.json";
const ACTIVE_GENERATION_FILENAME: &str = ".active-policy-generation";
const GENERATIONS_SUBDIR: &str = ".policy-generations";
/// Successful publications retain their immutable generation directories so
/// crash recovery never depends on deleting the formerly active policy. Bound
/// that retention explicitly: a trusted-but-runaway broker must not turn valid
/// signed updates into an unbounded root-filesystem write primitive. Operators
/// can archive inactive generations out of band after investigating the audit
/// trail; the daemon never guesses which historical evidence is disposable.
const MAX_STORED_POLICY_GENERATIONS: usize = 1_024;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RULE_BYTES: u64 = 1024 * 1024;
pub const MAX_PUBLISH_BUNDLE_BYTES: usize = 160 * 1024;

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

/// A fully verified manifest and its derived evaluator snapshot, staged but
/// not yet visible to policy evaluation. Watcher-driven reloads use this
/// boundary to durably authorize the exact candidate before committing it.
#[derive(Debug)]
pub(crate) struct PreparedManifestReload {
    loaded: LoadedManifest,
    snapshot: PolicySnapshot,
}

impl PreparedManifestReload {
    pub(crate) fn loaded(&self) -> &LoadedManifest {
        &self.loaded
    }
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
    #[error("pinned-key file at {path} is not a strict Ed25519 authority key: {source_message}")]
    PinnedKeyMalformed {
        path: PathBuf,
        source_message: String,
    },
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
    RuleDigestFailed { reason: String, issues: Vec<String> },
    #[error("manifest rule identity preflight failed: {issues:?}")]
    RuleIdentityPreflight { issues: Vec<String> },
    #[error("policy snapshot construction failed: {source_message}")]
    PolicySnapshot { source_message: String },
    #[error("manifest fortress id {got:?} does not match configured fortress {expected:?}")]
    FortressMismatch { expected: String, got: String },
    #[error("manifest generation rollback/refork refused: candidate={candidate}, high_water={high_water}")]
    GenerationRollback { candidate: u64, high_water: u64 },
    #[error("manifest high-water state failed at {path}: {source_message}")]
    HighWaterIo {
        path: PathBuf,
        source_message: String,
    },
    #[error(
        "active policy pointer was switched but the in-process commit became indeterminate: {source_message}"
    )]
    PublicationCommitIndeterminate { source_message: String },
}

impl ManifestStoreError {
    /// True only after publication crossed the active-pointer commit point.
    /// The caller must withdraw readiness and restart so disk and memory are
    /// reconciled from the fully verified immutable generation.
    pub(crate) fn requires_supervised_restart(&self) -> bool {
        matches!(self, Self::PublicationCommitIndeterminate { .. })
    }
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
    expected_fortress_id: String,
    high_water_path: PathBuf,
    current: Option<LoadedManifest>,
    current_snapshot: Option<PolicySnapshot>,
}

impl ManifestStore {
    /// Construct a store with the pinned key already loaded. Used by the
    /// daemon at boot, where pinned-key load is a refuse-to-start gate.
    pub fn new(
        policy_dir: PathBuf,
        pinned_key_path: PathBuf,
        pinned_key: [u8; 32],
        expected_fortress_id: String,
    ) -> Self {
        let high_water_path = policy_dir.join(MANIFEST_HIGH_WATER_FILENAME);
        Self {
            policy_dir,
            pinned_key_path,
            pinned_key,
            expected_fortress_id,
            high_water_path,
            current: None,
            current_snapshot: None,
        }
    }

    /// Read the pinned-key file from disk and return the raw 32-byte
    /// verifying key. Used by callers that want to refuse-to-start when the
    /// pin file is missing or malformed.
    pub fn load_pinned_key(path: &Path) -> Result<[u8; 32], ManifestStoreError> {
        let bytes = read_bounded_regular_no_follow(path, 32, true).map_err(|err| {
            ManifestStoreError::PinnedKeyIo {
                path: path.to_path_buf(),
                source_message: err.to_string(),
            }
        })?;
        if bytes.len() != 32 {
            return Err(ManifestStoreError::PinnedKeyLength {
                path: path.to_path_buf(),
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        parse_strict_verifying_key(&arr).map_err(|err| ManifestStoreError::PinnedKeyMalformed {
            path: path.to_path_buf(),
            source_message: err.to_string(),
        })?;
        Ok(arr)
    }

    /// Atomically replace the pinned-key file on disk with `new_key`. Used
    /// after a cross-signed rotation envelope has verified AND received
    /// operator approval (operator-approval gating lands in Checkpoint 3).
    pub fn persist_new_pinned_key(&mut self, new_key: [u8; 32]) -> Result<(), ManifestStoreError> {
        use std::os::unix::fs::OpenOptionsExt;
        parse_strict_verifying_key(&new_key).map_err(|err| {
            ManifestStoreError::PinnedKeyMalformed {
                path: self.pinned_key_path.clone(),
                source_message: err.to_string(),
            }
        })?;
        let parent =
            self.pinned_key_path
                .parent()
                .ok_or_else(|| ManifestStoreError::PinnedKeyIo {
                    path: self.pinned_key_path.clone(),
                    source_message: "pinned key path has no parent".to_string(),
                })?;
        let tmp = parent.join(format!(".pinned.key.{:016x}.tmp", OsRng.next_u64()));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&tmp)
            .map_err(|err| ManifestStoreError::PinnedKeyIo {
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
        fs::rename(&tmp, &self.pinned_key_path).map_err(|err| ManifestStoreError::PinnedKeyIo {
            path: self.pinned_key_path.clone(),
            source_message: err.to_string(),
        })?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|err| ManifestStoreError::PinnedKeyIo {
                path: parent.to_path_buf(),
                source_message: err.to_string(),
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

    /// Verify and derive the next manifest generation without changing the
    /// live policy. The returned value owns the exact bytes and snapshot that
    /// [`Self::commit_prepared_reload`] later installs, so a policy rewrite
    /// between authorization and commit cannot substitute another generation.
    fn prepare_reload(&self) -> Result<PreparedManifestReload, ManifestStoreError> {
        let loaded = load_signed_manifest_from_disk(&self.policy_dir, &self.pinned_key)?;
        self.prepare_loaded(loaded, true)
    }

    fn prepare_loaded(
        &self,
        loaded: LoadedManifest,
        allow_exact_reclaim: bool,
    ) -> Result<PreparedManifestReload, ManifestStoreError> {
        if loaded.signed.manifest.fortress_id != self.expected_fortress_id {
            return Err(ManifestStoreError::FortressMismatch {
                expected: self.expected_fortress_id.clone(),
                got: loaded.signed.manifest.fortress_id.clone(),
            });
        }
        if let Some(high_water) = read_high_water(&self.high_water_path)? {
            if high_water.fortress_id != self.expected_fortress_id {
                return Err(ManifestStoreError::FortressMismatch {
                    expected: self.expected_fortress_id.clone(),
                    got: high_water.fortress_id,
                });
            }
            let candidate_generation = loaded.signed.manifest.generation;
            let same_committed_manifest = candidate_generation == high_water.generation
                && loaded.manifest_signature_b64url == high_water.manifest_signature_b64url;
            if candidate_generation <= high_water.generation
                && !(allow_exact_reclaim && same_committed_manifest)
            {
                return Err(ManifestStoreError::GenerationRollback {
                    candidate: candidate_generation,
                    high_water: high_water.generation,
                });
            }
        }
        let snapshot = PolicySnapshot::from_loaded_manifest(&loaded)?;
        Ok(PreparedManifestReload { loaded, snapshot })
    }

    /// Commit a previously verified, owned reload candidate. This operation is
    /// intentionally infallible: watcher code performs the required durable
    /// precommit audit before calling it.
    fn commit_prepared_reload(
        &mut self,
        prepared: PreparedManifestReload,
    ) -> Result<&LoadedManifest, ManifestStoreError> {
        persist_high_water(
            &self.high_water_path,
            &ManifestHighWater {
                fortress_id: self.expected_fortress_id.clone(),
                generation: prepared.loaded.signed.manifest.generation,
                manifest_signature_b64url: prepared.loaded.manifest_signature_b64url.clone(),
            },
        )?;
        self.current = Some(prepared.loaded);
        self.current_snapshot = Some(prepared.snapshot);
        Ok(self
            .current
            .as_ref()
            .expect("prepared reload committed above"))
    }

    /// Sole production mutation primitive. `authorize` receives the exact
    /// owned candidate that will be committed; an error leaves prior state
    /// untouched. The callback is expected to return only after its durable
    /// receipt exists.
    pub(crate) fn reload_with_authorization<E>(
        &mut self,
        authorize: impl FnOnce(&LoadedManifest) -> Result<(), E>,
    ) -> Result<&LoadedManifest, AuthorizedReloadError<E>> {
        let prepared = self
            .prepare_reload()
            .map_err(AuthorizedReloadError::Verify)?;
        authorize(prepared.loaded()).map_err(AuthorizedReloadError::Authorization)?;
        self.commit_prepared_reload(prepared)
            .map_err(AuthorizedReloadError::Verify)
    }

    /// Publish one complete authenticated policy bundle without accepting any
    /// caller-controlled filesystem path. The bundle is written into a fresh
    /// root-owned generation directory, verified from those exact bytes, then
    /// made current by one fsynced pointer-file rename. A crash before the
    /// pointer leaves the old bundle active; a crash after it leaves the fully
    /// durable new bundle active for restart reconciliation.
    pub(crate) fn publish_bundle_with_authorization<E>(
        &mut self,
        manifest_bytes: &[u8],
        rules: &[(String, Vec<u8>)],
        authorize: impl FnOnce(&LoadedManifest) -> Result<(), E>,
    ) -> Result<&LoadedManifest, AuthorizedReloadError<E>> {
        let total = manifest_bytes.len().saturating_add(
            rules
                .iter()
                .map(|(name, body)| name.len().saturating_add(body.len()))
                .sum::<usize>(),
        );
        if total > MAX_PUBLISH_BUNDLE_BYTES {
            return Err(AuthorizedReloadError::Verify(
                ManifestStoreError::ManifestIo {
                    path: self.policy_dir.clone(),
                    source_message: format!(
                    "policy publication bundle is {total} bytes (cap {MAX_PUBLISH_BUNDLE_BYTES})"
                ),
                },
            ));
        }
        let generations = self.policy_dir.join(GENERATIONS_SUBDIR);
        ensure_secure_directory(&generations).map_err(AuthorizedReloadError::Verify)?;
        enforce_generation_quota(&generations).map_err(AuthorizedReloadError::Verify)?;
        let generation_name = format!("g-{:016x}", OsRng.next_u64());
        let staged = generations.join(&generation_name);
        fs::create_dir(&staged).map_err(|err| {
            AuthorizedReloadError::Verify(ManifestStoreError::ManifestIo {
                path: staged.clone(),
                source_message: err.to_string(),
            })
        })?;
        let mut staged_guard = StagedPolicyDir::new(staged.clone());
        set_mode(&staged, 0o700).map_err(AuthorizedReloadError::Verify)?;
        let staged_rules = staged.join(RULES_SUBDIR);
        fs::create_dir(&staged_rules).map_err(|err| {
            AuthorizedReloadError::Verify(ManifestStoreError::ManifestIo {
                path: staged_rules.clone(),
                source_message: err.to_string(),
            })
        })?;
        set_mode(&staged_rules, 0o700).map_err(AuthorizedReloadError::Verify)?;

        let mut supplied = std::collections::HashSet::new();
        for (name, body) in rules {
            if name.is_empty()
                || name.len() > 255
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.contains('\\')
                || name.as_bytes().contains(&0)
            {
                return Err(AuthorizedReloadError::Verify(
                    ManifestStoreError::RuleIdentityPreflight {
                        issues: vec![format!("unsafe supplied rule filename {name:?}")],
                    },
                ));
            }
            if !supplied.insert(name.clone()) {
                return Err(AuthorizedReloadError::Verify(
                    ManifestStoreError::RuleIdentityPreflight {
                        issues: vec![format!("duplicate supplied rule file {name:?}")],
                    },
                ));
            }
            write_new_synced_file(&staged_rules.join(name), body, 0o600)
                .map_err(AuthorizedReloadError::Verify)?;
        }
        sync_directory(&staged_rules).map_err(AuthorizedReloadError::Verify)?;
        write_new_synced_file(&staged.join(MANIFEST_FILENAME), manifest_bytes, 0o600)
            .map_err(AuthorizedReloadError::Verify)?;
        sync_directory(&staged).map_err(AuthorizedReloadError::Verify)?;
        sync_directory(&generations).map_err(AuthorizedReloadError::Verify)?;

        let loaded = load_signed_manifest_from_exact_dir(&staged, &self.pinned_key)
            .map_err(AuthorizedReloadError::Verify)?;
        let referenced: std::collections::HashSet<_> = loaded
            .signed
            .manifest
            .rules
            .iter()
            .map(|entry| entry.file.clone())
            .collect();
        if supplied != referenced {
            return Err(AuthorizedReloadError::Verify(
                ManifestStoreError::RuleIdentityPreflight {
                    issues: vec![
                        "supplied rule set is not exactly the manifest-referenced set".to_string(),
                    ],
                },
            ));
        }
        let prepared = self
            .prepare_loaded(loaded, false)
            .map_err(AuthorizedReloadError::Verify)?;
        authorize(prepared.loaded()).map_err(AuthorizedReloadError::Authorization)?;

        let pointer_tmp = self.policy_dir.join(format!(
            ".{ACTIVE_GENERATION_FILENAME}.{:016x}.tmp",
            OsRng.next_u64()
        ));
        write_new_synced_file(&pointer_tmp, generation_name.as_bytes(), 0o600)
            .map_err(AuthorizedReloadError::Verify)?;
        if let Err(err) = fs::rename(
            &pointer_tmp,
            self.policy_dir.join(ACTIVE_GENERATION_FILENAME),
        ) {
            // This is still before the activation commit point. Best-effort
            // removal prevents a persistently invalid destination from filling
            // the root-owned policy directory with pointer temporaries; the
            // immutable staged generation remains guarded and is removed below.
            let cleanup = fs::remove_file(&pointer_tmp);
            let _ = sync_directory(&self.policy_dir);
            return Err(AuthorizedReloadError::Verify(
                ManifestStoreError::ManifestIo {
                    path: self.policy_dir.join(ACTIVE_GENERATION_FILENAME),
                    source_message: match cleanup {
                        Ok(()) => err.to_string(),
                        Err(cleanup_err) => format!(
                            "{err}; additionally failed to remove pointer temporary {}: {cleanup_err}",
                            pointer_tmp.display()
                        ),
                    },
                },
            ));
        }
        // The pointer now names this complete directory. Preserve it even if a
        // later fsync/high-water write reports failure so restart can reconcile
        // the fully staged active generation.
        staged_guard.keep();
        sync_directory(&self.policy_dir).map_err(|err| {
            AuthorizedReloadError::Verify(ManifestStoreError::PublicationCommitIndeterminate {
                source_message: format!("active-pointer parent fsync failed after rename: {err}"),
            })
        })?;
        self.commit_prepared_reload(prepared).map_err(|err| {
            AuthorizedReloadError::Verify(ManifestStoreError::PublicationCommitIndeterminate {
                source_message: format!(
                    "active pointer is durable but high-water/in-memory commit failed: {err}"
                ),
            })
        })
    }

    /// Try to reload the manifest from disk and rebuild the derived
    /// [`PolicySnapshot`]. On success returns a reference to the new
    /// current `LoadedManifest`. On any failure (signature verify, rule
    /// digest, snapshot construction) the `current` and `current_snapshot`
    /// fields are left untouched (F-2 disposition: keep prior good policy
    /// in force) and the caller surfaces the error to Sanctuary main as a
    /// `PolicyReloadResponse` with `ok: false`.
    #[cfg(test)]
    pub(crate) fn reload(&mut self) -> Result<&LoadedManifest, ManifestStoreError> {
        let prepared = self.prepare_reload()?;
        self.commit_prepared_reload(prepared)
    }
}

struct StagedPolicyDir {
    path: PathBuf,
    keep: bool,
}

impl StagedPolicyDir {
    fn new(path: PathBuf) -> Self {
        Self { path, keep: false }
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for StagedPolicyDir {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o022 == 0
            {
                let _ = fs::remove_dir_all(&self.path);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum AuthorizedReloadError<E> {
    Verify(ManifestStoreError),
    Authorization(E),
}

/// Read + parse + verify a SignedManifest from `<policy_dir>/manifest.json`,
/// then read + SHA-256-verify every referenced rule file from
/// `<policy_dir>/rules/<file>`. Returns a `LoadedManifest` snapshot on full
/// success; any failure aborts before mutating any caller state.
pub fn load_signed_manifest_from_disk(
    policy_dir: &Path,
    pinned_key: &[u8; 32],
) -> Result<LoadedManifest, ManifestStoreError> {
    let exact_dir = resolve_active_policy_dir(policy_dir)?;
    load_signed_manifest_from_exact_dir(&exact_dir, pinned_key)
}

fn load_signed_manifest_from_exact_dir(
    policy_dir: &Path,
    pinned_key: &[u8; 32],
) -> Result<LoadedManifest, ManifestStoreError> {
    let manifest_path = policy_dir.join(MANIFEST_FILENAME);
    let raw_bytes = read_bounded_regular_no_follow(&manifest_path, MAX_MANIFEST_BYTES, true)
        .map_err(|err| ManifestStoreError::ManifestIo {
            path: manifest_path.clone(),
            source_message: err.to_string(),
        })?;
    let raw = std::str::from_utf8(&raw_bytes).map_err(|err| ManifestStoreError::ManifestParse {
        path: manifest_path.clone(),
        source_message: err.to_string(),
    })?;

    // Parse the manifest envelope (manifest body + signature wrapper).
    let parsed: ParsedSignedManifest =
        serde_json::from_str(raw).map_err(|err| ManifestStoreError::ManifestParse {
            path: manifest_path.clone(),
            source_message: err.to_string(),
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

    let preflight_issues = preflight_manifest_rule_entries(&signed.manifest.rules);
    if !preflight_issues.is_empty() {
        return Err(ManifestStoreError::RuleIdentityPreflight {
            issues: preflight_issues,
        });
    }

    let rules_dir = policy_dir.join(RULES_SUBDIR);
    let rules_dir_fd = open_rules_directory_no_follow(&rules_dir)?;
    let mut rule_files: HashMap<String, Vec<u8>> = HashMap::new();
    for entry in &signed.manifest.rules {
        let bytes = read_rule_relative_no_follow(&rules_dir_fd, &entry.file).map_err(|err| {
            ManifestStoreError::RuleFileIo {
                file: entry.file.clone(),
                source_message: err,
            }
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

/// Linux `openat` binds the final component to the opened rules-directory
/// descriptor and `O_NOFOLLOW` refuses a symlink at either boundary. This
/// prevents manifest fields from acquiring path authority. A same-UID attacker
/// can still replace policy files before the directory descriptor is opened.
fn open_rules_directory_no_follow(rules_dir: &Path) -> Result<fs::File, ManifestStoreError> {
    let path = CString::new(rules_dir.as_os_str().as_bytes()).map_err(|_| {
        ManifestStoreError::RuleFileIo {
            file: RULES_SUBDIR.to_string(),
            source_message: "rules directory path contains NUL".to_string(),
        }
    })?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ManifestStoreError::RuleFileIo {
            file: RULES_SUBDIR.to_string(),
            source_message: std::io::Error::last_os_error().to_string(),
        });
    }
    // Safety: `fd` is a successful `open` result and ownership transfers to
    // File, which closes it even on a later per-rule refusal.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn read_rule_relative_no_follow(rules_dir: &fs::File, filename: &str) -> Result<Vec<u8>, String> {
    let component = CString::new(filename).map_err(|_| "rule filename contains NUL".to_string())?;
    let fd = unsafe {
        libc::openat(
            rules_dir.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|err| err.to_string())?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() > MAX_RULE_BYTES
        || metadata.uid() != unsafe { libc::geteuid() }
        || mode & 0o022 != 0
    {
        return Err(format!(
            "rule is not a daemon-owned, non-writable-by-others, single-link bounded regular file (size={}, links={}, uid={}, mode={mode:o}, cap={MAX_RULE_BYTES})",
            metadata.len(), metadata.nlink(), metadata.uid()
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_RULE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;
    if bytes.len() as u64 > MAX_RULE_BYTES {
        return Err(format!(
            "rule exceeded {MAX_RULE_BYTES}-byte cap during read"
        ));
    }
    Ok(bytes)
}

fn read_bounded_regular_no_follow(
    path: &Path,
    cap: u64,
    require_single_link: bool,
) -> io::Result<Vec<u8>> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file()
        || metadata.len() > cap
        || (require_single_link && metadata.nlink() != 1)
        || metadata.uid() != unsafe { libc::geteuid() }
        || mode & 0o022 != 0
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
            "not a daemon-owned, non-writable-by-others, single-link bounded regular file (size={}, links={}, uid={}, mode={mode:o}, cap={cap})",
            metadata.len(), metadata.nlink(), metadata.uid()
        )));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(cap + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeded {cap}-byte cap during read"),
        ));
    }
    Ok(bytes)
}

fn resolve_active_policy_dir(policy_dir: &Path) -> Result<PathBuf, ManifestStoreError> {
    let pointer = policy_dir.join(ACTIVE_GENERATION_FILENAME);
    let raw = match read_bounded_regular_no_follow(&pointer, 64, true) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(policy_dir.to_path_buf()),
        Err(err) => {
            return Err(ManifestStoreError::ManifestIo {
                path: pointer,
                source_message: err.to_string(),
            })
        }
    };
    let name = std::str::from_utf8(&raw).map_err(|err| ManifestStoreError::ManifestIo {
        path: pointer.clone(),
        source_message: format!("active policy pointer is not UTF-8: {err}"),
    })?;
    if name.len() != 18
        || !name.starts_with("g-")
        || !name[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ManifestStoreError::ManifestIo {
            path: pointer,
            source_message: "active policy pointer has invalid generation grammar".to_string(),
        });
    }
    let generations_dir = policy_dir.join(GENERATIONS_SUBDIR);
    let generations_metadata =
        fs::symlink_metadata(&generations_dir).map_err(|err| ManifestStoreError::ManifestIo {
            path: generations_dir.clone(),
            source_message: err.to_string(),
        })?;
    if !generations_metadata.file_type().is_dir()
        || generations_metadata.uid() != unsafe { libc::geteuid() }
        || generations_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ManifestStoreError::ManifestIo {
            path: generations_dir,
            source_message: "policy generation root is not a secure daemon-owned directory"
                .to_string(),
        });
    }
    let generation_dir = generations_dir.join(name);
    let metadata =
        fs::symlink_metadata(&generation_dir).map_err(|err| ManifestStoreError::ManifestIo {
            path: generation_dir.clone(),
            source_message: err.to_string(),
        })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ManifestStoreError::ManifestIo {
            path: generation_dir,
            source_message: "active policy generation is not a secure daemon-owned directory"
                .to_string(),
        });
    }
    Ok(generation_dir)
}

fn ensure_secure_directory(path: &Path) -> Result<(), ManifestStoreError> {
    match fs::create_dir(path) {
        Ok(()) => set_mode(path, 0o700)?,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(ManifestStoreError::ManifestIo {
                path: path.to_path_buf(),
                source_message: err.to_string(),
            })
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|err| ManifestStoreError::ManifestIo {
        path: path.to_path_buf(),
        source_message: err.to_string(),
    })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ManifestStoreError::ManifestIo {
            path: path.to_path_buf(),
            source_message: "publication directory is not a secure daemon-owned directory"
                .to_string(),
        });
    }
    sync_directory(path.parent().unwrap_or(path))
}

fn is_generation_name(name: &str) -> bool {
    name.len() == 18
        && name.starts_with("g-")
        && name[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Refuse a new immutable generation before creating any file when the
/// root-owned retention area has reached its explicit bound. Count every entry
/// with the daemon's own generation grammar, including a symlink/preplant: an
/// ambiguous slot consumes quota and fails closed instead of being ignored.
fn enforce_generation_quota(generations: &Path) -> Result<(), ManifestStoreError> {
    let entries = fs::read_dir(generations).map_err(|err| ManifestStoreError::ManifestIo {
        path: generations.to_path_buf(),
        source_message: err.to_string(),
    })?;
    let mut count = 0usize;
    for entry in entries {
        let entry = entry.map_err(|err| ManifestStoreError::ManifestIo {
            path: generations.to_path_buf(),
            source_message: err.to_string(),
        })?;
        if entry.file_name().to_str().is_some_and(is_generation_name) {
            count += 1;
            if count >= MAX_STORED_POLICY_GENERATIONS {
                return Err(ManifestStoreError::ManifestIo {
                    path: generations.to_path_buf(),
                    source_message: format!(
                        "policy generation retention reached cap {MAX_STORED_POLICY_GENERATIONS}; investigate and archive inactive generations before publishing"
                    ),
                });
            }
        }
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), ManifestStoreError> {
    let mut permissions = fs::symlink_metadata(path)
        .map_err(|err| ManifestStoreError::ManifestIo {
            path: path.to_path_buf(),
            source_message: err.to_string(),
        })?
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).map_err(|err| ManifestStoreError::ManifestIo {
        path: path.to_path_buf(),
        source_message: err.to_string(),
    })
}

fn write_new_synced_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ManifestStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|err| ManifestStoreError::ManifestIo {
            path: path.to_path_buf(),
            source_message: err.to_string(),
        })?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|err| ManifestStoreError::ManifestIo {
            path: path.to_path_buf(),
            source_message: err.to_string(),
        })
}

fn sync_directory(path: &Path) -> Result<(), ManifestStoreError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| ManifestStoreError::ManifestIo {
            path: path.to_path_buf(),
            source_message: err.to_string(),
        })
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestHighWater {
    fortress_id: String,
    generation: u64,
    manifest_signature_b64url: String,
}

fn read_high_water(path: &Path) -> Result<Option<ManifestHighWater>, ManifestStoreError> {
    let bytes = match read_bounded_regular_no_follow(path, 4096, true) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(ManifestStoreError::HighWaterIo {
                path: path.to_path_buf(),
                source_message: err.to_string(),
            })
        }
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|err| ManifestStoreError::HighWaterIo {
            path: path.to_path_buf(),
            source_message: format!("invalid high-water state: {err}"),
        })
}

fn persist_high_water(path: &Path, value: &ManifestHighWater) -> Result<(), ManifestStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .ok_or_else(|| ManifestStoreError::HighWaterIo {
            path: path.to_path_buf(),
            source_message: "high-water path has no parent".to_string(),
        })?;
    let bytes = serde_json::to_vec(value).map_err(|err| ManifestStoreError::HighWaterIo {
        path: path.to_path_buf(),
        source_message: err.to_string(),
    })?;
    let tmp = parent.join(format!(
        ".{MANIFEST_HIGH_WATER_FILENAME}.{:016x}.tmp",
        OsRng.next_u64()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|err| ManifestStoreError::HighWaterIo {
            path: tmp.clone(),
            source_message: err.to_string(),
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|err| ManifestStoreError::HighWaterIo {
            path: tmp.clone(),
            source_message: err.to_string(),
        })?;
    fs::rename(&tmp, path).map_err(|err| ManifestStoreError::HighWaterIo {
        path: path.to_path_buf(),
        source_message: err.to_string(),
    })?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| ManifestStoreError::HighWaterIo {
            path: parent.to_path_buf(),
            source_message: err.to_string(),
        })
}

/// Mirrors the on-disk signed manifest envelope shape so serde_json can
/// deserialize without forcing the public `SignedManifest` to derive
/// `Default`. Kept private; callers see `SignedManifest` only.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ParsedSignedManifest {
    manifest: AllowlistManifest,
    signature: ManifestSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::castle_wall_signing_key_id;
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
            "{{\"id\":\"{rule_id}\",\"schema_version\":1,\"created_at\":\"2026-05-05T00:00:00Z\",\"match\":{{\"ip\":[\"203.0.113.7\"]}},\"disposition\":\"allow\"}}"
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
            let rule_id = format!("uuid-{}", i);
            let file = format!("{}.json", rule_id);
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
        let habeas_file = format!("{}.json", crate::habeas::HABEAS_LOCAL_RULE_ID);
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
            generation: 1,
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
                signing_key_id: castle_wall_signing_key_id(&pinned_key).unwrap(),
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

    fn rewrite_signed_manifest(
        policy: &WrittenPolicy,
        mutate: impl FnOnce(&mut AllowlistManifest),
    ) {
        let path = policy.dir.path().join(MANIFEST_FILENAME);
        let raw = fs::read_to_string(&path).unwrap();
        let parsed: ParsedSignedManifest = serde_json::from_str(&raw).unwrap();
        let mut manifest = parsed.manifest;
        mutate(&mut manifest);
        let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let signature = policy.signing_key.sign(&canonical);
        let envelope = ParsedSignedManifest {
            manifest,
            signature: ManifestSignature {
                signature_scheme: crate::constants::SIGNATURE_SCHEME_V1.to_string(),
                signing_key_id: castle_wall_signing_key_id(&policy.pinned_key).unwrap(),
                signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(signature.to_bytes()),
            },
        };
        fs::write(path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
    }

    fn wire_bundle(policy: &WrittenPolicy) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        let manifest = fs::read(policy.dir.path().join(MANIFEST_FILENAME)).unwrap();
        let parsed: ParsedSignedManifest = serde_json::from_slice(&manifest).unwrap();
        let rules = parsed
            .manifest
            .rules
            .iter()
            .map(|entry| {
                (
                    entry.file.clone(),
                    fs::read(policy.dir.path().join(RULES_SUBDIR).join(&entry.file)).unwrap(),
                )
            })
            .collect();
        (manifest, rules)
    }

    #[test]
    fn load_signed_manifest_happy_path() {
        let policy = write_valid_policy(2);
        let loaded =
            load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).expect("load");
        // 2 synthetic rules + the always-present habeas local lane.
        assert_eq!(loaded.rule_count, 3);
        assert_eq!(loaded.rule_files.len(), 3);
        assert!(loaded.rule_files.contains_key("uuid-0.json"));
    }

    #[test]
    fn load_fails_when_manifest_signature_does_not_verify() {
        let policy = write_valid_policy(1);
        // Replace the pinned key with a different one so the existing
        // signature cannot verify against it.
        let attacker = SigningKey::generate(&mut OsRng);
        let bad_pin = attacker.verifying_key().to_bytes();
        let err = load_signed_manifest_from_disk(policy.dir.path(), &bad_pin).unwrap_err();
        assert!(matches!(
            err,
            ManifestStoreError::ManifestSignatureFailed { .. }
        ));
    }

    #[test]
    fn load_fails_when_rule_file_missing() {
        let policy = write_valid_policy(1);
        // Remove the rule file referenced by the manifest.
        fs::remove_file(policy.dir.path().join(RULES_SUBDIR).join("uuid-0.json")).unwrap();
        let err =
            load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
        assert!(matches!(err, ManifestStoreError::RuleFileIo { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_symlinked_rule_without_reading_outside_rules_directory() {
        use std::os::unix::fs::symlink;

        let policy = write_valid_policy(1);
        let outside = policy.dir.path().join("outside-sentinel.json");
        let sentinel = b"outside sentinel remains unchanged";
        fs::write(&outside, sentinel).unwrap();
        let rule_path = policy.dir.path().join(RULES_SUBDIR).join("uuid-0.json");
        fs::remove_file(&rule_path).unwrap();
        symlink(&outside, &rule_path).unwrap();

        let err =
            load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
        assert!(matches!(err, ManifestStoreError::RuleFileIo { .. }));
        assert_eq!(fs::read(outside).unwrap(), sentinel);
    }

    #[test]
    fn load_rejects_all_identity_preflight_failures_before_rule_reads() {
        let policy = write_valid_policy(1);
        let raw = fs::read_to_string(policy.dir.path().join(MANIFEST_FILENAME)).unwrap();
        let parsed: super::ParsedSignedManifest = serde_json::from_str(&raw).unwrap();
        let mut manifest = parsed.manifest;
        manifest.rules.push(ManifestRuleEntry {
            rule_id: "uuid-0".to_string(),
            file: "uuid-0.json".to_string(),
            sha256: "00".to_string(),
        });
        manifest.rules.push(ManifestRuleEntry {
            rule_id: "unsafe/path".to_string(),
            file: "unsafe/path.json".to_string(),
            sha256: "00".to_string(),
        });
        let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let signature = policy.signing_key.sign(&canonical);
        let envelope = ParsedSignedManifest {
            manifest,
            signature: ManifestSignature {
                signature_scheme: crate::constants::SIGNATURE_SCHEME_V1.to_string(),
                signing_key_id: castle_wall_signing_key_id(&policy.pinned_key).unwrap(),
                signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(signature.to_bytes()),
            },
        };
        fs::write(
            policy.dir.path().join(MANIFEST_FILENAME),
            serde_json::to_string(&envelope).unwrap(),
        )
        .unwrap();

        let err =
            load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
        match err {
            ManifestStoreError::RuleIdentityPreflight { issues } => assert!(issues.len() >= 3),
            other => panic!("expected identity preflight refusal, got {other:?}"),
        }
    }

    #[test]
    fn load_fails_when_rule_file_tampered() {
        let policy = write_valid_policy(1);
        // Swap the rule file body without updating the manifest digest.
        fs::write(
            policy.dir.path().join(RULES_SUBDIR).join("uuid-0.json"),
            b"{\"a\":2}",
        )
        .unwrap();
        let err =
            load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
        assert!(matches!(err, ManifestStoreError::RuleDigestFailed { .. }));
    }

    #[test]
    fn load_fails_when_manifest_missing() {
        let policy = write_valid_policy(1);
        fs::remove_file(policy.dir.path().join(MANIFEST_FILENAME)).unwrap();
        let err =
            load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
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
        let err =
            load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key).unwrap_err();
        assert!(matches!(
            err,
            ManifestStoreError::ManifestSchemaUnsupported { .. }
        ));
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
            "deadbeef".to_string(),
        );
        assert!(store.current().is_none());
        let loaded = store.reload().expect("reload");
        // 1 synthetic rule + the habeas local lane.
        assert_eq!(loaded.rule_count, 2);
        assert!(store.current().is_some());
    }

    #[test]
    fn broker_publication_activates_complete_bundle_and_restart_reclaims_it() {
        let policy = write_valid_policy(1);
        let (manifest, rules) = wire_bundle(&policy);
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            policy.dir.path().join("pinned.key"),
            policy.pinned_key,
            "deadbeef".to_string(),
        );
        let mut authorized = false;
        store
            .publish_bundle_with_authorization(&manifest, &rules, |_| {
                authorized = true;
                Ok::<_, ()>(())
            })
            .expect("publish complete bundle");
        assert!(authorized);
        assert!(policy.dir.path().join(ACTIVE_GENERATION_FILENAME).is_file());

        let mut restarted = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            policy.dir.path().join("pinned.key"),
            policy.pinned_key,
            "deadbeef".to_string(),
        );
        restarted.reload().expect("restart reclaims active bundle");
        assert_eq!(restarted.current().unwrap().rule_count, 2);

        // An authenticated request replay is not a restart reclaim and cannot
        // manufacture another activation at the committed generation.
        assert!(matches!(
            restarted.publish_bundle_with_authorization(&manifest, &rules, |_| Ok::<_, ()>(())),
            Err(AuthorizedReloadError::Verify(
                ManifestStoreError::GenerationRollback { .. }
            ))
        ));
    }

    #[test]
    fn refused_or_oversized_bundle_never_switches_active_pointer() {
        let policy = write_valid_policy(1);
        let (manifest, mut rules) = wire_bundle(&policy);
        rules[0].1[0] ^= 1;
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            policy.dir.path().join("pinned.key"),
            policy.pinned_key,
            "deadbeef".to_string(),
        );
        assert!(store
            .publish_bundle_with_authorization(&manifest, &rules, |_| Ok::<_, ()>(()))
            .is_err());
        assert!(!policy.dir.path().join(ACTIVE_GENERATION_FILENAME).exists());

        let oversized = vec![0u8; MAX_PUBLISH_BUNDLE_BYTES + 1];
        assert!(store
            .publish_bundle_with_authorization(&oversized, &[], |_| Ok::<_, ()>(()))
            .is_err());
        assert!(!policy.dir.path().join(ACTIVE_GENERATION_FILENAME).exists());
    }

    #[test]
    fn publication_requires_exact_rule_set_and_durable_authorization() {
        let policy = write_valid_policy(1);
        let (manifest, rules) = wire_bundle(&policy);
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            policy.dir.path().join("pinned.key"),
            policy.pinned_key,
            "deadbeef".to_string(),
        );

        let mut missing = rules.clone();
        missing.pop();
        assert!(store
            .publish_bundle_with_authorization(&manifest, &missing, |_| Ok::<_, ()>(()))
            .is_err());
        let mut extra = rules.clone();
        extra.push(("unreferenced.json".to_string(), b"{}".to_vec()));
        assert!(matches!(
            store.publish_bundle_with_authorization(&manifest, &extra, |_| Ok::<_, ()>(())),
            Err(AuthorizedReloadError::Verify(
                ManifestStoreError::RuleIdentityPreflight { .. }
            ))
        ));
        assert!(matches!(
            store.publish_bundle_with_authorization(&manifest, &rules, |_| Err("audit refused")),
            Err(AuthorizedReloadError::Authorization("audit refused"))
        ));
        assert!(!policy.dir.path().join(ACTIVE_GENERATION_FILENAME).exists());
        assert!(store.current().is_none());
    }

    #[test]
    fn publication_refuses_wrong_fortress_and_wrong_signing_key() {
        let wrong_fortress = write_valid_policy(1);
        rewrite_signed_manifest(&wrong_fortress, |manifest| {
            manifest.fortress_id = "feedface".to_string();
        });
        let (manifest, rules) = wire_bundle(&wrong_fortress);
        let mut fortress_store = ManifestStore::new(
            wrong_fortress.dir.path().to_path_buf(),
            wrong_fortress.dir.path().join("pinned.key"),
            wrong_fortress.pinned_key,
            "deadbeef".to_string(),
        );
        assert!(matches!(
            fortress_store.publish_bundle_with_authorization(
                &manifest,
                &rules,
                |_| Ok::<_, ()>(())
            ),
            Err(AuthorizedReloadError::Verify(
                ManifestStoreError::FortressMismatch { .. }
            ))
        ));

        let wrong_key = write_valid_policy(1);
        let (manifest, rules) = wire_bundle(&wrong_key);
        let unrelated_pin = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let mut key_store = ManifestStore::new(
            wrong_key.dir.path().to_path_buf(),
            wrong_key.dir.path().join("pinned.key"),
            unrelated_pin,
            "deadbeef".to_string(),
        );
        assert!(matches!(
            key_store.publish_bundle_with_authorization(&manifest, &rules, |_| Ok::<_, ()>(())),
            Err(AuthorizedReloadError::Verify(
                ManifestStoreError::ManifestSignatureFailed { .. }
            ))
        ));
        assert!(!wrong_key
            .dir
            .path()
            .join(ACTIVE_GENERATION_FILENAME)
            .exists());
    }

    #[test]
    fn concurrent_publications_converge_on_highest_generation() {
        use std::sync::{Arc, Barrier, Mutex};

        let policy = write_valid_policy(1);
        rewrite_signed_manifest(&policy, |manifest| manifest.generation = 2);
        let generation_two = wire_bundle(&policy);
        rewrite_signed_manifest(&policy, |manifest| manifest.generation = 3);
        let generation_three = wire_bundle(&policy);
        let store = Arc::new(Mutex::new(ManifestStore::new(
            policy.dir.path().to_path_buf(),
            policy.dir.path().join("pinned.key"),
            policy.pinned_key,
            "deadbeef".to_string(),
        )));
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |bundle: (Vec<u8>, Vec<(String, Vec<u8>)>)| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .lock()
                    .unwrap()
                    .publish_bundle_with_authorization(&bundle.0, &bundle.1, |_| Ok::<_, ()>(()))
                    .map(|loaded| loaded.signed.manifest.generation)
            })
        };
        let two = spawn(generation_two);
        let three = spawn(generation_three);
        barrier.wait();
        let _ = two.join().unwrap();
        let _ = three.join().unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .current()
                .unwrap()
                .signed
                .manifest
                .generation,
            3
        );
        let restarted = load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key)
            .expect("active pointer names the highest complete generation");
        assert_eq!(restarted.signed.manifest.generation, 3);
    }

    #[cfg(unix)]
    #[test]
    fn broker_publication_refuses_symlinked_generation_root() {
        use std::os::unix::fs::symlink;
        let policy = write_valid_policy(1);
        let (manifest, rules) = wire_bundle(&policy);
        let outside = TempDir::new().unwrap();
        symlink(outside.path(), policy.dir.path().join(GENERATIONS_SUBDIR)).unwrap();
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            policy.dir.path().join("pinned.key"),
            policy.pinned_key,
            "deadbeef".to_string(),
        );
        assert!(store
            .publish_bundle_with_authorization(&manifest, &rules, |_| Ok::<_, ()>(()))
            .is_err());
        assert!(!policy.dir.path().join(ACTIVE_GENERATION_FILENAME).exists());
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[test]
    fn broker_publication_refuses_before_writing_when_generation_quota_is_full() {
        let policy = write_valid_policy(1);
        let (manifest, rules) = wire_bundle(&policy);
        let generations = policy.dir.path().join(GENERATIONS_SUBDIR);
        fs::create_dir(&generations).unwrap();
        for index in 0..MAX_STORED_POLICY_GENERATIONS {
            fs::create_dir(generations.join(format!("g-{index:016x}"))).unwrap();
        }
        let before = fs::read_dir(&generations).unwrap().count();
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            policy.dir.path().join("pinned.key"),
            policy.pinned_key,
            "deadbeef".to_string(),
        );

        let error = store
            .publish_bundle_with_authorization(&manifest, &rules, |_| Ok::<_, ()>(()))
            .unwrap_err();

        assert!(matches!(
            error,
            AuthorizedReloadError::Verify(ManifestStoreError::ManifestIo {
                source_message,
                ..
            }) if source_message.contains("retention reached cap")
        ));
        assert_eq!(fs::read_dir(generations).unwrap().count(), before);
        assert!(!policy.dir.path().join(ACTIVE_GENERATION_FILENAME).exists());
        assert!(store.current().is_none());
    }

    #[test]
    fn restart_ignores_an_incomplete_unpointed_generation() {
        let policy = write_valid_policy(1);
        let abandoned = policy
            .dir
            .path()
            .join(GENERATIONS_SUBDIR)
            .join("g-0000000000000001");
        fs::create_dir_all(abandoned.join(RULES_SUBDIR)).unwrap();
        fs::write(abandoned.join(MANIFEST_FILENAME), b"partial").unwrap();

        let loaded = load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key)
            .expect("an unpointed partial stage cannot replace the flat active policy");
        assert_eq!(loaded.signed.manifest.generation, 1);
    }

    #[cfg(unix)]
    #[test]
    fn restart_refuses_a_symlinked_active_pointer() {
        use std::os::unix::fs::symlink;
        let policy = write_valid_policy(1);
        let outside = policy.dir.path().join("outside-pointer");
        fs::write(&outside, b"g-0000000000000001").unwrap();
        symlink(&outside, policy.dir.path().join(ACTIVE_GENERATION_FILENAME)).unwrap();
        assert!(matches!(
            load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key),
            Err(ManifestStoreError::ManifestIo { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn restart_refuses_a_symlinked_generation_root_before_following_active_pointer() {
        use std::os::unix::fs::symlink;
        let policy = write_valid_policy(1);
        let (manifest, rules) = wire_bundle(&policy);
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            policy.dir.path().join("pinned.key"),
            policy.pinned_key,
            "deadbeef".to_string(),
        );
        store
            .publish_bundle_with_authorization(&manifest, &rules, |_| Ok::<_, ()>(()))
            .expect("publish pointed generation");

        let generations = policy.dir.path().join(GENERATIONS_SUBDIR);
        let preserved = policy.dir.path().join("preserved-generations");
        fs::rename(&generations, &preserved).unwrap();
        symlink(&preserved, &generations).unwrap();

        assert!(matches!(
            load_signed_manifest_from_disk(policy.dir.path(), &policy.pinned_key),
            Err(ManifestStoreError::ManifestIo {
                source_message,
                ..
            }) if source_message.contains("generation root")
        ));
    }

    #[test]
    fn store_refuses_manifest_for_another_fortress() {
        let policy = write_valid_policy(1);
        rewrite_signed_manifest(&policy, |manifest| {
            manifest.fortress_id = "feedface".to_string();
        });
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            policy.dir.path().join("pinned.key"),
            policy.pinned_key,
            "deadbeef".to_string(),
        );
        assert!(matches!(
            store.reload(),
            Err(ManifestStoreError::FortressMismatch { .. })
        ));
    }

    #[test]
    fn durable_generation_high_water_refuses_rollback_and_same_generation_refork() {
        let policy = write_valid_policy(1);
        let pinned_path = policy.dir.path().join("pinned.key");
        let mut first = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            pinned_path.clone(),
            policy.pinned_key,
            "deadbeef".to_string(),
        );
        first.reload().expect("commit generation one");

        // A fresh process may idempotently reclaim the exact committed bytes.
        let mut restarted = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            pinned_path.clone(),
            policy.pinned_key,
            "deadbeef".to_string(),
        );
        restarted.reload().expect("exact restart reclaim");

        // Re-signing different content at the same generation is a refork,
        // and a lower generation is a rollback. Both remain refused after a
        // process restart because the high-water file is durable.
        rewrite_signed_manifest(&policy, |manifest| {
            manifest.issued_at = "2026-05-06T00:00:00Z".to_string();
        });
        assert!(matches!(
            restarted.reload(),
            Err(ManifestStoreError::GenerationRollback {
                candidate: 1,
                high_water: 1
            })
        ));
        rewrite_signed_manifest(&policy, |manifest| {
            manifest.generation = 0;
        });
        assert!(matches!(
            restarted.reload(),
            Err(ManifestStoreError::GenerationRollback {
                candidate: 0,
                high_water: 1
            })
        ));
    }

    #[test]
    fn higher_generation_cannot_overwrite_another_fortress_high_water() {
        let policy = write_valid_policy(1);
        let pinned_path = policy.dir.path().join("pinned.key");
        let mut store = ManifestStore::new(
            policy.dir.path().to_path_buf(),
            pinned_path,
            policy.pinned_key,
            "deadbeef".to_string(),
        );
        store.reload().expect("commit generation one");
        let committed_signature = store
            .current()
            .expect("committed manifest")
            .manifest_signature_b64url
            .clone();
        persist_high_water(
            &store.high_water_path,
            &ManifestHighWater {
                fortress_id: "feedface".to_string(),
                generation: 1,
                manifest_signature_b64url: committed_signature,
            },
        )
        .expect("replace high-water fixture");
        rewrite_signed_manifest(&policy, |manifest| {
            manifest.generation = 2;
        });

        assert!(matches!(
            store.reload(),
            Err(ManifestStoreError::FortressMismatch { expected, got })
                if expected == "deadbeef" && got == "feedface"
        ));
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
            "deadbeef".to_string(),
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
            "deadbeef".to_string(),
        );
        store.reload().expect("first reload");
        let prior_snapshot_rule_count = store.current_snapshot().unwrap().rules.len();

        // Re-write the rule body to something whose SHA-256 still matches
        // the manifest entry but does NOT parse as AllowlistRule. We do this
        // by re-signing the manifest with a body that has the digest the
        // manifest entry expects. The simpler equivalent: rewrite the rule
        // body AND the manifest digest to keep the digest aligned but the
        // body invalid as AllowlistRule.
        let rule_path = policy.dir.path().join(RULES_SUBDIR).join("uuid-0.json");
        let bad_body = b"{\"id\":\"uuid-0\",\"schema_version\":1}";
        // Can't simply overwrite, the digest in the existing manifest no
        // longer matches. The real demonstration here is via the snapshot
        // construction error class. Use the lower-level constructor to
        // exercise it.
        fs::write(&rule_path, bad_body).unwrap();
        // Bump the manifest's digest entry to match this body so the
        // digest gate doesn't trip first; the snapshot construction is the
        // gate we want to exercise.
        let raw = fs::read_to_string(policy.dir.path().join(MANIFEST_FILENAME)).unwrap();
        // Compute the new digest and resign the manifest.
        use base64::Engine;
        use ed25519_dalek::Signer;
        let new_digest = sha256_hex(bad_body);
        // Parse the existing signed manifest, swap the digest, re-canonicalize, re-sign.
        let parsed: super::ParsedSignedManifest = serde_json::from_str(&raw).unwrap();
        let mut new_manifest = parsed.manifest.clone();
        new_manifest.generation += 1;
        if let Some(entry) = new_manifest.rules.first_mut() {
            entry.sha256 = new_digest;
        }
        let canonical =
            canonicalize_to_bytes(&serde_json::to_value(&new_manifest).unwrap()).unwrap();
        let new_sig = policy.signing_key.sign(&canonical);
        let new_sig_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(new_sig.to_bytes());
        let new_envelope = SignedManifest {
            manifest: new_manifest,
            signature: ManifestSignature {
                signature_scheme: crate::constants::SIGNATURE_SCHEME_V1.to_string(),
                signing_key_id: castle_wall_signing_key_id(&policy.pinned_key).unwrap(),
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
            "deadbeef".to_string(),
        );
        store.reload().expect("first reload");
        let prior_signature = store.current().unwrap().manifest_signature_b64url.clone();

        // Tamper with the rule file. Reload should fail; current should
        // still hold the prior good snapshot.
        fs::write(
            policy.dir.path().join(RULES_SUBDIR).join("uuid-0.json"),
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
            "deadbeef".to_string(),
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

    #[test]
    fn load_and_persist_reject_weak_authority_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pinned.key");
        let mut identity = [0u8; 32];
        identity[0] = 1;
        fs::write(&path, identity).unwrap();
        assert!(matches!(
            ManifestStore::load_pinned_key(&path),
            Err(ManifestStoreError::PinnedKeyMalformed { .. })
        ));

        let signing = SigningKey::generate(&mut OsRng);
        fs::write(&path, signing.verifying_key().to_bytes()).unwrap();
        let mut store = ManifestStore::new(
            dir.path().join("policy"),
            path,
            signing.verifying_key().to_bytes(),
            "deadbeef".to_string(),
        );
        assert!(matches!(
            store.persist_new_pinned_key(identity),
            Err(ManifestStoreError::PinnedKeyMalformed { .. })
        ));
    }

    // Suppress unused-field warnings on WrittenPolicy.signing_key in tests
    // that don't need to re-sign.
    #[allow(dead_code)]
    fn _signing_key_field_used(p: &WrittenPolicy) -> &SigningKey {
        &p.signing_key
    }
}
