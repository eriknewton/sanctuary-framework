//! Root-owned, AUTHENTICATED ownership journal for the host nftables runtime.
//! (blockers 2, 3, 4)
//!
//! The acquisition path takes the host lock, then creates the `sanctuary-castle`
//! table. Without a durable record of "this daemon is mid-acquisition / owns
//! this table", a crash, `SIGKILL`, or systemd `TimeoutStartSec` between the
//! atomic `create` and the in-memory capture of the table handles would leave a
//! table behind that a naive restart cannot tell apart from a foreign table: the
//! old behavior REFUSED any pre-existing `sanctuary-castle` table, so the very
//! table this daemon created would wedge every subsequent restart forever. But
//! the fix must NOT be "blanket-clean any pre-existing table by name" — that
//! would clobber genuinely foreign state.
//!
//! This journal is the discriminator. It records a strict state machine —
//! `Preparing` before the kernel mutation, `Owned` (with the captured handles)
//! after — bound to a random per-acquisition `marker` (also stamped as the nft
//! table comment), the current `boot_id` (nft state does not survive a reboot,
//! so a journal from a prior boot never authorizes reclaiming a live table), and
//! a `source` identity (the daemon binary path). On restart, reclaim happens
//! ONLY when the journal schema, marker, boot id, source, and the live table's
//! EXACT owned identity all agree; anything else refuses without deleting, so a
//! foreign table is never adopted or clobbered.
//!
//! ## Authentication (blocker 3)
//!
//! The record is not merely a file: it carries an HMAC-SHA256 tag over its exact
//! canonical bytes, keyed by a persistent machine-local key that is generated and
//! read ONLY under the root-owned `StateDirectory` (`/var/lib/sanctuary`, 0700).
//! A record whose MAC does not verify — a hand-edited handle, a truncated file, a
//! record re-keyed by a different machine — is a HARD ERROR, never silently
//! treated as "no journal": a corrupt ownership proof must fail the daemon
//! closed, not fall through to a fresh create that could clobber a live owned
//! table. The key file and the journal file are both opened `O_NOFOLLOW`
//! (no symlink traversal), required to be regular files owned by the current
//! (root, in production) euid with no group/other permission bits, and bounded in
//! length. Verification is constant-time; temporary key and MAC material is
//! zeroed where practical.
//!
//! Durability is a propagated claim, not an assumption: `store_atomic` fsyncs the
//! temp file AND the parent directory and SURFACES either fsync's failure — an
//! atomic rename over an unsynced file is not durable across power loss, so a
//! failed sync fails the write closed rather than returning a false success.
//!
//! The journal is written to an explicit, locked-down `StateDirectory`
//! (`/var/lib/sanctuary`, provisioned root-owned by the systemd unit) rather than
//! an ephemeral `RuntimeDirectory`, so it survives a service restart and —
//! together with the boot-id guard — a reboot. The state-machine DECISION is a
//! pure function over `(journal, table_present, boot_id, source)` so every crash
//! boundary is unit-testable on any host without a kernel; the file I/O around it
//! is thin.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Production journal location. Under the systemd unit's `StateDirectory=`
/// (`/var/lib/sanctuary`, root-owned, 0700) so it persists across service
/// restarts and reboots. Must stay under the unit's
/// `StateDirectory`/`ReadWritePaths`; a path the unit does not make writable
/// would fail the durable write and (correctly) fail the daemon closed.
///
/// The host lock lives in the SAME persistent StateDirectory (see
/// `runtime_lock::DEFAULT_HOST_LOCK_PATH`, pinned by
/// `tests/systemd_unit.rs::unit_provisions_the_durable_state_directory_for_the_ownership_journal`),
/// NOT in `/run`. Both are overridable together through
/// `config::LinuxRuntimePaths` so a test never touches the operator's copies.
pub const DEFAULT_OWNERSHIP_JOURNAL_PATH: &str = "/var/lib/sanctuary/nft-ownership.json";

/// Production journal-authentication key location. Also under the root-owned
/// `StateDirectory`. The MAC key never leaves this file, is 0600 root-owned, and
/// is generated on first acquisition. A journal present with this key MISSING is
/// a refusal (an unauthenticated record cannot prove ownership). Must match the
/// `StateDirectory`/`ReadWritePaths` in the systemd unit.
pub const DEFAULT_JOURNAL_AUTH_KEY_PATH: &str = "/var/lib/sanctuary/nft-journal-auth.key";

/// Linux boot-id path. Its value changes on every boot, so a journal that
/// records a different boot id than the running kernel cannot describe a live
/// table (nft state is cleared on reboot). (blocker 4)
#[cfg(target_os = "linux")]
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Current schema version of the journal. A journal recording any other version
/// is treated as UNUSABLE and a HARD ERROR (not silently None), so an old-format
/// record can never authorize a reclaim and never fails open.
pub const JOURNAL_SCHEMA_VERSION: u32 = 1;

/// Length of the journal-authentication key in bytes (256-bit HMAC-SHA256 key).
pub const AUTH_KEY_LEN: usize = 32;

/// Domain-separation prefix for the journal MAC. Binding the tag to this domain
/// prevents a MAC minted for any other purpose (or by any other subsystem sharing
/// the key file, of which there are none) from ever validating here.
const MAC_DOMAIN: &[u8] = b"sanctuary.castle-wall.nft-ownership-journal.v1\n";

/// Upper bound on the on-disk authenticated envelope size. The envelope is a tiny
/// fixed-shape JSON object (base64 record + hex MAC + scheme tag); a file larger
/// than this is malformed/hostile and is rejected before any parse, bounding the
/// work an attacker who can write the StateDirectory could force.
const MAX_ENVELOPE_BYTES: u64 = 8 * 1024;

/// Upper bound on the decoded record bytes (the canonical `OwnershipJournal`
/// JSON). The record is a handful of short fields; anything larger is malformed.
const MAX_RECORD_BYTES: usize = 2 * 1024;

/// The MAC scheme tag stamped in the envelope so a future scheme change is
/// explicit rather than a silent reinterpretation of the tag bytes.
const MAC_SCHEME_V1: &str = "hmac-sha256-v1";

/// Errors from journal persistence, authentication, and durability.
#[derive(Debug, thiserror::Error)]
pub enum OwnershipJournalError {
    #[error("failed to write ownership journal at {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read ownership journal at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A durability step (file or parent-directory fsync) failed. Surfaced rather
    /// than swallowed: an atomic rename over an unsynced file is not durable, so a
    /// failed sync must fail the write closed.
    #[error("failed to durably sync ownership journal at {path}: {source}")]
    Durability {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The journal file exists but the authentication key is absent. An
    /// unauthenticated record is not an ownership proof, so this is a refusal, not
    /// a silent fresh start.
    #[error("ownership journal at {journal} exists but its authentication key {key} is missing; refusing (an unauthenticated record is not proof)")]
    KeyMissing { journal: PathBuf, key: PathBuf },
    /// The authentication key file failed a security precondition (not a regular
    /// file, a symlink, wrong owner, group/other-accessible mode, or wrong
    /// length). A key that cannot be trusted cannot authenticate a proof.
    #[error("journal authentication key at {path} is unsafe: {reason}")]
    UnsafeKey { path: PathBuf, reason: String },
    /// The journal file failed a security precondition (not a regular file, a
    /// symlink, wrong owner, or a group/other-accessible mode).
    #[error("ownership journal at {path} is unsafe: {reason}")]
    UnsafeJournal { path: PathBuf, reason: String },
    /// The journal is present but its authenticated envelope is malformed, its MAC
    /// does not verify, its schema is unknown, or its record does not parse. This
    /// is a HARD ERROR (never `None`): a corrupt ownership proof must fail the
    /// daemon closed, so it can neither authorize a reclaim nor be mistaken for a
    /// clean first boot that would create/clobber over live state.
    #[error("ownership journal at {path} is corrupt or unauthenticated: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    /// The Linux boot id could not be read or validated. (blocker 4) An empty or
    /// unreadable boot id is a hard activation error, never an empty string that
    /// would let a prior-boot record masquerade as current.
    #[error("could not read a valid Linux boot id at {path}: {reason}")]
    BootId { path: PathBuf, reason: String },
}

/// The identity fields every journal record carries. All must match on restart
/// for a reclaim to be authorized. `marker` is the random per-acquisition nonce
/// (also the nft table comment); `boot_id` scopes the record to the boot whose
/// kernel state it describes; `source` is the daemon binary identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalIdentity {
    pub schema_version: u32,
    pub marker: String,
    pub boot_id: String,
    pub source: String,
}

impl JournalIdentity {
    /// Whether this record's identity matches the running context AND the
    /// current schema. A mismatch (old schema, prior boot, different binary,
    /// different nonce) means "not this daemon's current acquisition."
    fn matches(&self, boot_id: &str, source: &str) -> bool {
        self.schema_version == JOURNAL_SCHEMA_VERSION
            && self.boot_id == boot_id
            && self.source == source
    }
}

/// The persisted ownership state machine. `Preparing` is written durably BEFORE
/// the atomic `create`; `Owned` is written durably AFTER the handles are
/// captured and verified (the "finalize" step). The journal is cleared ONLY by
/// the explicit disarm path, AFTER the owned table's deletion and absence are
/// positively confirmed — never by ordinary shutdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OwnershipJournal {
    /// About to create (or mid-create) the table with `identity.marker`. If a
    /// crash happens here, a restart can prove the live table is ours by
    /// matching the marker, then finalize; a live table whose marker differs is
    /// foreign and refused.
    Preparing { identity: JournalIdentity },
    /// The table was created, its handles captured and verified. This is the
    /// steady state a systemd restart reclaims from.
    Owned {
        identity: JournalIdentity,
        table_handle: u64,
        base_chain_handle: u64,
    },
}

impl OwnershipJournal {
    fn identity(&self) -> &JournalIdentity {
        match self {
            OwnershipJournal::Preparing { identity } => identity,
            OwnershipJournal::Owned { identity, .. } => identity,
        }
    }
}

/// The on-disk AUTHENTICATED envelope: the exact canonical record bytes plus an
/// HMAC over `MAC_DOMAIN || record_bytes`. Storing the record verbatim (base64)
/// and MACing those exact bytes avoids any JSON-canonicalization ambiguity — the
/// bytes verified are byte-for-byte the bytes parsed.
#[derive(Debug, Serialize, Deserialize)]
struct AuthenticatedEnvelope {
    /// MAC scheme tag; only `hmac-sha256-v1` is accepted in this schema.
    mac_scheme: String,
    /// Base64 (standard, padded) of the canonical `OwnershipJournal` JSON bytes.
    record_b64: String,
    /// Hex of the HMAC tag over `MAC_DOMAIN || record_bytes`.
    mac_hex: String,
}

// ---------------------------------------------------------------------------
// Authentication key.
// ---------------------------------------------------------------------------

/// A machine-local journal-authentication key. Held only transiently in memory;
/// the bytes are zeroed on drop so key material does not linger. (blocker 3)
pub struct JournalAuthKey {
    bytes: [u8; AUTH_KEY_LEN],
}

impl JournalAuthKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for JournalAuthKey {
    fn drop(&mut self) {
        zeroize(&mut self.bytes);
    }
}

impl std::fmt::Debug for JournalAuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key bytes.
        f.write_str("JournalAuthKey(<redacted>)")
    }
}

/// Overwrite a buffer with zeros using volatile writes so the compiler cannot
/// elide the scrub. Used for key/MAC scratch buffers.
fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Open a StateDirectory file for reading with `O_NOFOLLOW` (no symlink
/// traversal) and validate it is a REGULAR file owned by our (root, in
/// production) euid with no group/other permission bits. Returns the open file so
/// the caller reads from the exact validated inode. Any precondition failure is a
/// hard error (the caller maps it to `UnsafeKey`/`UnsafeJournal`).
fn open_secure_regular_file(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        // O_NOFOLLOW: if the final path component is a symlink, open fails with
        // ELOOP rather than following it out of the locked-down StateDirectory.
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("cannot open O_NOFOLLOW: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat open file: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        // Owner must be the current effective uid. In production the daemon is
        // root (systemd `User=root`) and the StateDirectory is root-owned 0700,
        // so this IS the root-ownership check; it also rejects a file planted by
        // any other uid. Testable on any platform: a file we did not create as
        // ourselves fails here.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(format!(
                "owned by uid {} but this process runs as euid {euid}",
                meta.uid()
            ));
        }
        // No group/other permission bits: the proof/key is private to the owner.
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "mode {mode:04o} grants group/other access; must be 0600/0700-private"
            ));
        }
    }
    Ok(file)
}

/// Read the authentication key if present. Returns:
/// * `Ok(None)` — the key file does not exist (first boot, before any store).
/// * `Ok(Some(key))` — a present key that passed every security precondition.
/// * `Err(UnsafeKey)` — a present-but-unsafe key (symlink, wrong owner/mode,
///   wrong length). A key that cannot be trusted is a hard error.
pub fn read_auth_key(path: &Path) -> Result<Option<JournalAuthKey>, OwnershipJournalError> {
    let mut file = match open_secure_regular_file(path) {
        Ok(f) => f,
        Err(reason) => {
            // Distinguish "absent" (Ok(None), first boot) from "present but
            // unsafe" (hard error). O_NOFOLLOW open of an absent path is NotFound.
            if path_is_absent(path) {
                return Ok(None);
            }
            return Err(OwnershipJournalError::UnsafeKey {
                path: path.to_path_buf(),
                reason,
            });
        }
    };
    let mut buf = Vec::with_capacity(AUTH_KEY_LEN + 1);
    // Bound the read so an oversized key file cannot balloon memory.
    // `File` implements both `Read` and `Write`, so `by_ref` is ambiguous (E0034);
    // name the `Read` trait explicitly so this is the read-side reborrow feeding
    // `Read::take`, preserving the strict length check below.
    Read::by_ref(&mut file)
        .take((AUTH_KEY_LEN + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|source| OwnershipJournalError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if buf.len() != AUTH_KEY_LEN {
        zeroize(&mut buf);
        return Err(OwnershipJournalError::UnsafeKey {
            path: path.to_path_buf(),
            reason: format!(
                "expected exactly {AUTH_KEY_LEN} key bytes, found {}",
                buf.len()
            ),
        });
    }
    let mut bytes = [0u8; AUTH_KEY_LEN];
    bytes.copy_from_slice(&buf);
    zeroize(&mut buf);
    Ok(Some(JournalAuthKey { bytes }))
}

/// Whether `path` refers to nothing (NotFound). Used to tell "absent key" (fine)
/// apart from "present but unsafe key" (hard error) after an `O_NOFOLLOW` open
/// failure, which reports NotFound for absence and ELOOP/others for a symlink.
fn path_is_absent(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        Ok(_) => false,
    }
}

/// Read the key, generating and persisting a fresh one under the StateDirectory
/// if absent. Used by the STORE path (an acquisition that writes a journal needs
/// a key). A present-but-unsafe key is still a hard error — generation happens
/// ONLY for a genuinely absent key, never over an untrusted one.
pub fn load_or_generate_auth_key(path: &Path) -> Result<JournalAuthKey, OwnershipJournalError> {
    if let Some(key) = read_auth_key(path)? {
        return Ok(key);
    }
    // Absent: generate a fresh 256-bit key from the kernel CSPRNG and persist it
    // 0600 under the (root-owned) StateDirectory, durably.
    let mut bytes = [0u8; AUTH_KEY_LEN];
    fill_random(&mut bytes).map_err(|source| OwnershipJournalError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    write_secret_file_atomic(path, &bytes)?;
    Ok(JournalAuthKey { bytes })
}

/// Fill a buffer with kernel CSPRNG bytes from `/dev/urandom`. Dependency-free
/// (matches the daemon's no-`rand`-feature stance) and always available on the
/// Linux hosts this path runs on and on the macOS dev host.
fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    let mut urandom = std::fs::File::open("/dev/urandom")?;
    urandom.read_exact(buf)
}

/// Atomically write a 0600 secret file: temp sibling (0600) -> fsync -> rename ->
/// fsync parent dir. Both fsync failures are surfaced (durability is a propagated
/// claim). The temp file uses an unpredictable 128-bit name and is opened with
/// `O_EXCL|O_NOFOLLOW`, so an existing path is never truncated or followed.
fn write_secret_file_atomic(path: &Path, secret: &[u8]) -> Result<(), OwnershipJournalError> {
    write_private_file_atomic(path, secret)
}

/// Open one new private temp file. `create_new` supplies `O_CREAT|O_EXCL`; the
/// explicit `O_NOFOLLOW` makes the no-symlink contract visible and defense in
/// depth across platform implementations. A collision is retried with fresh
/// kernel-random bytes and is never opened for truncation.
fn create_private_temp(parent: &Path, label: &str) -> std::io::Result<(PathBuf, std::fs::File)> {
    for _ in 0..128 {
        let mut nonce = [0u8; 16];
        fill_random(&mut nonce)?;
        let tmp = parent.join(format!(".{label}.{}.tmp", hex::encode(nonce)));
        zeroize(&mut nonce);
        match open_private_temp_at(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique private atomic-write temp file",
    ))
}

fn open_private_temp_at(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Best-effort cleanup inside the production StateDirectory trust boundary.
///
/// Production relies on systemd provisioning the parent as root-owned 0700, so
/// no unprivileged process can replace this unpredictable pathname. The inode
/// comparison avoids unlinking an already-observed replacement, but it is NOT an
/// atomic compare-and-unlink guarantee against a concurrent privileged writer:
/// Linux has no unlink-by-open-file-descriptor primitive, and replacement can
/// race the final pathname unlink. A privileged writer is outside this boundary.
fn remove_private_temp_best_effort(path: &Path, file: &std::fs::File) {
    use std::os::unix::fs::MetadataExt;
    let Ok(open_meta) = file.metadata() else {
        return;
    };
    let Ok(path_meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if path_meta.file_type().is_file()
        && path_meta.dev() == open_meta.dev()
        && path_meta.ino() == open_meta.ino()
    {
        let _ = std::fs::remove_file(path);
    }
}

/// Shared atomic private writer for the authentication key and authenticated
/// journal. It never opens an existing temp path. On pre-rename failure it makes
/// the best-effort, same-inode cleanup described above within the root-only 0700
/// parent-directory boundary; it does not claim atomicity against privileged
/// replacement.
fn write_private_file_atomic(path: &Path, contents: &[u8]) -> Result<(), OwnershipJournalError> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mk_write = |source: std::io::Error| OwnershipJournalError::Write {
        path: path.to_path_buf(),
        source,
    };
    let mk_sync = |source: std::io::Error| OwnershipJournalError::Durability {
        path: path.to_path_buf(),
        source,
    };

    let label = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "private".to_string());
    let (tmp, mut file) = create_private_temp(parent, &label).map_err(mk_write)?;
    if let Err(source) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        remove_private_temp_best_effort(&tmp, &file);
        return Err(mk_write(source));
    }
    if let Err(source) = file.write_all(contents) {
        remove_private_temp_best_effort(&tmp, &file);
        return Err(mk_write(source));
    }
    // Durability: fsync the file before the rename. An atomic rename over an
    // unsynced file is not durable across power loss.
    if let Err(source) = file.sync_all() {
        remove_private_temp_best_effort(&tmp, &file);
        return Err(mk_sync(source));
    }
    if let Err(source) = std::fs::rename(&tmp, path) {
        remove_private_temp_best_effort(&tmp, &file);
        return Err(mk_write(source));
    }
    // Durability: fsync the parent dir so the rename itself survives power loss.
    // A failure here is surfaced, not swallowed.
    let dir = std::fs::File::open(parent).map_err(mk_sync)?;
    dir.sync_all().map_err(mk_sync)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 + constant-time compare (dependency-free, matches the daemon's
// stance of implementing small stable primitives over adding crates).
// ---------------------------------------------------------------------------

/// HMAC-SHA256 over `msg`, keyed by `key`. Scratch buffers (the padded key and
/// pads) are zeroed before returning. (blocker 3: zero temporary MAC material.)
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for ((ipad_b, opad_b), k_b) in ipad.iter_mut().zip(opad.iter_mut()).zip(k.iter()) {
        *ipad_b ^= *k_b;
        *opad_b ^= *k_b;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let out = outer.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    // Scrub key-derived scratch.
    zeroize(&mut k);
    zeroize(&mut ipad);
    zeroize(&mut opad);
    tag
}

/// The domain-separated MAC tag for a record's canonical bytes.
fn record_mac(key: &JournalAuthKey, record_bytes: &[u8]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(MAC_DOMAIN.len() + record_bytes.len());
    msg.extend_from_slice(MAC_DOMAIN);
    msg.extend_from_slice(record_bytes);
    let tag = hmac_sha256(key.as_bytes(), &msg);
    zeroize(&mut msg);
    tag
}

/// Constant-time byte-slice equality. Compares in time independent of where the
/// first differing byte is, so a MAC check cannot be turned into a timing oracle.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Journal load / store (authenticated).
// ---------------------------------------------------------------------------

/// Load and AUTHENTICATE the journal.
///
/// * Absent journal file -> `Ok(None)` (first boot; there is nothing to reclaim).
/// * Present journal file with `key == None` -> `Err(KeyMissing)`: an
///   unauthenticated record is not an ownership proof, so it is a refusal.
/// * Present journal, MAC verifies, record parses at the current schema ->
///   `Ok(Some(journal))`.
/// * Present journal that is unsafe (symlink/owner/mode), oversized, malformed,
///   fails its MAC, or is at an unknown schema -> `Err(Corrupt/UnsafeJournal)`,
///   a HARD ERROR. A corrupt proof NEVER reads as `None`, so it can neither
///   authorize a reclaim nor be mistaken for a clean first boot.
pub fn load(
    path: &Path,
    key: Option<&JournalAuthKey>,
) -> Result<Option<OwnershipJournal>, OwnershipJournalError> {
    // Open the exact validated inode (O_NOFOLLOW, regular, owner/mode). Absence is
    // the only non-error; a present-but-unsafe file is a hard error.
    let mut file = match open_secure_regular_file(path) {
        Ok(f) => f,
        Err(reason) => {
            if path_is_absent(path) {
                return Ok(None);
            }
            return Err(OwnershipJournalError::UnsafeJournal {
                path: path.to_path_buf(),
                reason,
            });
        }
    };
    // The journal is present. It MUST be authenticated, so a missing key here is
    // a refusal, not a fresh start.
    let key = key.ok_or_else(|| OwnershipJournalError::KeyMissing {
        journal: path.to_path_buf(),
        key: PathBuf::from(DEFAULT_JOURNAL_AUTH_KEY_PATH),
    })?;

    // Bounded read of the envelope.
    // `File` implements both `Read` and `Write`, so `by_ref` is ambiguous (E0034);
    // name the `Read` trait explicitly so this is the read-side reborrow feeding
    // `Read::take`, preserving the strict envelope bound checked below.
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_ENVELOPE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| OwnershipJournalError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(OwnershipJournalError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("envelope exceeds {MAX_ENVELOPE_BYTES}-byte bound"),
        });
    }

    let corrupt = |reason: String| OwnershipJournalError::Corrupt {
        path: path.to_path_buf(),
        reason,
    };

    let envelope: AuthenticatedEnvelope = serde_json::from_slice(&bytes)
        .map_err(|e| corrupt(format!("envelope did not parse: {e}")))?;
    if envelope.mac_scheme != MAC_SCHEME_V1 {
        return Err(corrupt(format!(
            "unknown MAC scheme {:?} (expected {MAC_SCHEME_V1})",
            envelope.mac_scheme
        )));
    }

    use base64::Engine;
    let record_bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope.record_b64.as_bytes())
        .map_err(|e| corrupt(format!("record base64 did not decode: {e}")))?;
    if record_bytes.len() > MAX_RECORD_BYTES {
        return Err(corrupt(format!(
            "record exceeds {MAX_RECORD_BYTES}-byte bound"
        )));
    }
    let stored_mac = hex_decode(&envelope.mac_hex)
        .ok_or_else(|| corrupt("MAC hex did not decode".to_string()))?;

    // Constant-time MAC verification over the EXACT record bytes we will parse.
    let mut expected = record_mac(key, &record_bytes);
    let ok = ct_eq(&expected, &stored_mac);
    zeroize(&mut expected);
    if !ok {
        return Err(corrupt(
            "MAC does not verify (tampered, truncated, or wrong key)".to_string(),
        ));
    }

    let journal: OwnershipJournal = serde_json::from_slice(&record_bytes)
        .map_err(|e| corrupt(format!("authenticated record did not parse: {e}")))?;
    // Schema mismatch on an AUTHENTIC record is still a hard error, not a silent
    // None: an unusable proof must fail closed.
    if journal.identity().schema_version != JOURNAL_SCHEMA_VERSION {
        return Err(corrupt(format!(
            "record schema {} is not the current {JOURNAL_SCHEMA_VERSION}",
            journal.identity().schema_version
        )));
    }
    Ok(Some(journal))
}

/// Persist the journal DURABLY and AUTHENTICATED: serialize the record to
/// canonical bytes, MAC them, write the envelope to a sibling temp file, fsync
/// it, atomically rename it over the target, then fsync the directory. BOTH fsync
/// failures are surfaced (durability is a propagated claim; an atomic rename over
/// an unsynced file is not durable). A crash mid-write leaves either the old
/// record or the new one, never a torn file.
pub fn store_atomic(
    path: &Path,
    journal: &OwnershipJournal,
    key: &JournalAuthKey,
) -> Result<(), OwnershipJournalError> {
    let mk_write = |source: std::io::Error| OwnershipJournalError::Write {
        path: path.to_path_buf(),
        source,
    };

    let record_bytes = serde_json::to_vec(journal)
        .map_err(|e| mk_write(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
    let mut mac = record_mac(key, &record_bytes);
    use base64::Engine;
    let envelope = AuthenticatedEnvelope {
        mac_scheme: MAC_SCHEME_V1.to_string(),
        record_b64: base64::engine::general_purpose::STANDARD.encode(&record_bytes),
        mac_hex: hex::encode(mac),
    };
    zeroize(&mut mac);
    let json = serde_json::to_vec(&envelope)
        .map_err(|e| mk_write(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

    write_private_file_atomic(path, &json)
}

/// Delete the journal file. Used ONLY by the explicit disarm path, AFTER the
/// owned table's deletion and post-delete absence are positively confirmed —
/// never by ordinary shutdown. Absent file is fine (idempotent). A failure to
/// remove is surfaced so the disarm path can retain-and-fail rather than report a
/// spurious clear.
pub fn clear(path: &Path) -> Result<(), OwnershipJournalError> {
    clear_with_parent_sync(path, |parent| {
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()
    })
}

fn clear_with_parent_sync(
    path: &Path,
    sync_parent: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<(), OwnershipJournalError> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(OwnershipJournalError::Write {
                path: path.to_path_buf(),
                source,
            })
        }
    }
    // Durability of the unlink: fsync the parent dir so the removal survives a
    // power loss (the disarm path verifies absence, so a resurrected file after a
    // crash must not reappear as a live proof).
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    sync_parent(parent).map_err(|source| OwnershipJournalError::Durability {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Decode a hex string to bytes; `None` on any non-hex input (a malformed MAC is
/// treated as corrupt by the caller).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

/// The current boot id, read and VALIDATED from the kernel. (blocker 4) An
/// unreadable or empty boot id is a hard error, never an empty string: an empty
/// id would let a prior-boot record's empty id match and masquerade as current.
#[cfg(target_os = "linux")]
pub fn current_boot_id() -> Result<String, OwnershipJournalError> {
    read_boot_id_strict(Path::new(BOOT_ID_PATH))
}

/// Non-Linux hosts have no nft runtime and never reach the reclaim path; a fixed
/// sentinel keeps the journal serde tests runnable on the dev host.
#[cfg(not(target_os = "linux"))]
pub fn current_boot_id() -> Result<String, OwnershipJournalError> {
    Ok("non-linux-host".to_string())
}

/// Read and strictly validate a boot-id file. A read failure OR an
/// empty/whitespace-only value is a hard error. Pure over the path for
/// testability. (blocker 4)
#[cfg(any(target_os = "linux", test))]
fn read_boot_id_strict(path: &Path) -> Result<String, OwnershipJournalError> {
    let raw = std::fs::read_to_string(path).map_err(|e| OwnershipJournalError::BootId {
        path: path.to_path_buf(),
        reason: format!("read failed: {e}"),
    })?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err(OwnershipJournalError::BootId {
            path: path.to_path_buf(),
            reason: "boot id is empty".to_string(),
        });
    }
    Ok(trimmed)
}

/// The daemon binary identity, recorded so a journal written by a different
/// program cannot authorize a reclaim. Falls back to a fixed string when the
/// exe path is unavailable (still stable within a run).
pub fn current_source() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "castle-wall-daemon".to_string())
}

/// What the acquisition path should do after taking the host lock, given the
/// journal on disk and whether a `sanctuary-castle` table is live. This is the
/// crash-recovery state machine, pure so every boundary is unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReclaimDecision {
    /// The journal records an `Owned` table for THIS boot/source. Re-verify the
    /// live table still matches these exact handles+marker, then reclaim it.
    ReclaimOwned {
        table_handle: u64,
        base_chain_handle: u64,
        marker: String,
    },
    /// The journal records an interrupted `Preparing` acquisition for THIS
    /// boot/source and a table is live. Prove it is ours by matching `marker`,
    /// then capture handles and finalize; a marker mismatch means foreign.
    FinalizeInterrupted { marker: String },
    /// A table is live but no journal proves this daemon owns it (no journal, a
    /// prior-boot or foreign-source record). Refuse WITHOUT deleting: never adopt
    /// or clobber a table we cannot prove is ours. (A corrupt/unauthenticated
    /// journal never reaches here — `load` fails closed before `decide`.)
    RefuseForeign,
    /// GF1 (fail-closed): no live table, but the AUTHENTICATED journal proves
    /// THIS daemon owned (or was mid-prepare of) a `sanctuary-castle` table for
    /// the CURRENT boot+source. The table therefore VANISHED out from under a
    /// running daemon (an external `nft delete table` while agents are live).
    /// Treating this as `FreshCreate` would install an empty base chain with
    /// `policy accept` and no agent jumps, so every live cgroup member would
    /// egress with NO verdict: fail-OPEN. The caller must instead GUARANTEE a
    /// deny-all state (base chain that DROPS) before anything else, then refuse.
    /// A prior-boot record does NOT reach here (`identity.matches` requires the
    /// current boot id): a reboot clears both nftables and every agent, so there
    /// is nothing live to strand and `FreshCreate` is correct there.
    ReArmLostOwned,
    /// No live table. Any stale journal is moot; create fresh (a fresh `Preparing`
    /// overwrites a stale record — that is a rewrite of an un-owned slot, not the
    /// disarm-only clear of an owned proof).
    FreshCreate,
}

/// Decide the acquisition action from the durable journal and live-table
/// presence. (blockers 2, 3) Reclaim of a LIVE table is authorized only when the
/// record's schema, boot id, and source all match the running context; every
/// other combination either refuses (foreign table present) or starts fresh (no
/// table). The live table's EXACT identity is re-verified by the caller before
/// any reclaim — this function decides intent, not truth about the kernel. A
/// corrupt or unauthenticated journal never reaches this function: `load` returns
/// a hard error for it, so the acquisition fails closed before deciding.
pub fn decide(
    journal: Option<&OwnershipJournal>,
    table_present: bool,
    boot_id: &str,
    source: &str,
) -> ReclaimDecision {
    // No live table. GF1: distinguish a genuine fresh/stale start from an owned
    // table that VANISHED under a running daemon. If the AUTHENTICATED journal
    // proves THIS boot+source owned (or was mid-prepare of) a table, the table
    // was deleted out from under live agents; `FreshCreate` would reinstall an
    // empty `policy accept` base (fail-OPEN), so route to `ReArmLostOwned` and
    // let the caller guarantee deny-all first. Otherwise (no record, or a
    // prior-boot/foreign-source record that `identity.matches` rejects) a reboot
    // cleared nftables and every agent, so there is nothing live to strand:
    // start fresh (a stale record is overwritten, never disarm-cleared).
    if !table_present {
        return match journal {
            Some(OwnershipJournal::Owned { identity, .. })
            | Some(OwnershipJournal::Preparing { identity })
                if identity.matches(boot_id, source) =>
            {
                ReclaimDecision::ReArmLostOwned
            }
            _ => ReclaimDecision::FreshCreate,
        };
    }
    match journal {
        Some(OwnershipJournal::Owned {
            identity,
            table_handle,
            base_chain_handle,
        }) if identity.matches(boot_id, source) => ReclaimDecision::ReclaimOwned {
            table_handle: *table_handle,
            base_chain_handle: *base_chain_handle,
            marker: identity.marker.clone(),
        },
        Some(OwnershipJournal::Preparing { identity }) if identity.matches(boot_id, source) => {
            ReclaimDecision::FinalizeInterrupted {
                marker: identity.marker.clone(),
            }
        }
        // A table is present but the journal does not prove current ownership
        // (absent, or a wrong boot/source record).
        _ => ReclaimDecision::RefuseForeign,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn ident(marker: &str, boot: &str, source: &str) -> JournalIdentity {
        JournalIdentity {
            schema_version: JOURNAL_SCHEMA_VERSION,
            marker: marker.to_string(),
            boot_id: boot.to_string(),
            source: source.to_string(),
        }
    }

    fn test_key() -> JournalAuthKey {
        JournalAuthKey {
            bytes: [7u8; AUTH_KEY_LEN],
        }
    }

    #[test]
    fn round_trips_through_authenticated_atomic_store_and_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        let journal = OwnershipJournal::Owned {
            identity: ident("m", "boot-1", "src"),
            table_handle: 2,
            base_chain_handle: 1,
        };
        store_atomic(&path, &journal, &key).unwrap();
        assert_eq!(load(&path, Some(&key)).unwrap(), Some(journal));
    }

    #[cfg(unix)]
    #[test]
    fn private_temp_open_refuses_an_existing_symlink_without_touching_its_target() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let candidate = dir.path().join("candidate.tmp");
        std::fs::write(&target, b"do not truncate").unwrap();
        std::os::unix::fs::symlink(&target, &candidate).unwrap();

        let err = open_private_temp_at(&candidate)
            .expect_err("O_EXCL/O_NOFOLLOW temp create must refuse an existing symlink");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"do not truncate");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_private_writes_land_with_exact_owner_private_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret");
        write_secret_file_atomic(&path, b"secret").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn best_effort_temp_cleanup_leaves_an_already_observed_replacement() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("candidate.tmp");
        let held_path = dir.path().join("held.tmp");
        let file = open_private_temp_at(&path).unwrap();
        std::fs::rename(&path, &held_path).unwrap();
        std::fs::write(&path, b"foreign replacement").unwrap();

        remove_private_temp_best_effort(&path, &file);
        assert_eq!(std::fs::read(&path).unwrap(), b"foreign replacement");
    }

    #[test]
    fn failed_atomic_rename_cleans_up_the_created_temp_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("occupied-directory");
        std::fs::create_dir(&target).unwrap();
        assert!(write_secret_file_atomic(&target, b"secret").is_err());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "failed write left temp files: {leftovers:?}"
        );
    }

    #[test]
    fn absent_journal_loads_as_none() {
        let dir = TempDir::new().unwrap();
        let key = test_key();
        assert_eq!(
            load(&dir.path().join("missing.json"), Some(&key)).unwrap(),
            None
        );
    }

    #[test]
    fn present_journal_with_missing_key_is_a_refusal_not_a_fresh_start() {
        // blocker 3: an unauthenticated record is not a proof. A journal present
        // with the key absent must REFUSE (hard error), never read as None.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        store_atomic(
            &path,
            &OwnershipJournal::Preparing {
                identity: ident("m", "b", "s"),
            },
            &key,
        )
        .unwrap();
        let err = load(&path, None).expect_err("missing key with present journal must refuse");
        assert!(matches!(err, OwnershipJournalError::KeyMissing { .. }));
    }

    #[test]
    fn a_tampered_record_fails_the_mac_and_is_a_hard_error_never_none() {
        // Flip a byte inside the base64 record: the MAC no longer verifies, which
        // is Corrupt (hard error), NOT a silent None that would fail open.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        store_atomic(
            &path,
            &OwnershipJournal::Owned {
                identity: ident("m", "b", "s"),
                table_handle: 5,
                base_chain_handle: 4,
            },
            &key,
        )
        .unwrap();
        // Rewrite the envelope with a mutated record while keeping the old MAC.
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut env: AuthenticatedEnvelope = serde_json::from_str(&raw).unwrap();
        use base64::Engine;
        let mut rec = base64::engine::general_purpose::STANDARD
            .decode(env.record_b64.as_bytes())
            .unwrap();
        rec[0] ^= 0xff;
        env.record_b64 = base64::engine::general_purpose::STANDARD.encode(&rec);
        std::fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();
        let err = load(&path, Some(&key)).expect_err("tampered record must be a hard error");
        assert!(matches!(err, OwnershipJournalError::Corrupt { .. }));
    }

    #[test]
    fn a_wrong_key_fails_the_mac_as_a_hard_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        store_atomic(
            &path,
            &OwnershipJournal::Preparing {
                identity: ident("m", "b", "s"),
            },
            &test_key(),
        )
        .unwrap();
        let wrong = JournalAuthKey {
            bytes: [9u8; AUTH_KEY_LEN],
        };
        let err = load(&path, Some(&wrong)).expect_err("wrong key must fail the MAC");
        assert!(matches!(err, OwnershipJournalError::Corrupt { .. }));
    }

    #[test]
    fn a_truncated_envelope_is_a_hard_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        store_atomic(
            &path,
            &OwnershipJournal::Preparing {
                identity: ident("m", "b", "s"),
            },
            &key,
        )
        .unwrap();
        let raw = std::fs::read(&path).unwrap();
        std::fs::write(&path, &raw[..raw.len() / 2]).unwrap();
        let err = load(&path, Some(&key)).expect_err("truncation must be a hard error");
        assert!(matches!(err, OwnershipJournalError::Corrupt { .. }));
    }

    #[test]
    fn a_garbled_non_json_journal_is_a_hard_error_never_none() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("j.json");
        // Write the fixture 0600 (owner-private) so it passes the load-path
        // owner/mode precondition and reaches the parse step this test targets;
        // `std::fs::write` would leave it 0644 under a 022 umask and (correctly)
        // trip the UnsafeJournal gate first, which is a different hard error.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        f.write_all(b"not json at all").unwrap();
        drop(f);
        let key = test_key();
        let err = load(&path, Some(&key)).expect_err("garbled journal is a hard error");
        assert!(matches!(err, OwnershipJournalError::Corrupt { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_journal_is_rejected_as_unsafe() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        store_atomic(
            &path,
            &OwnershipJournal::Preparing {
                identity: ident("m", "b", "s"),
            },
            &key,
        )
        .unwrap();
        // Loosen the mode: group/other bits must make the load refuse.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load(&path, Some(&key)).expect_err("group/other-accessible journal is unsafe");
        assert!(matches!(err, OwnershipJournalError::UnsafeJournal { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_journal_is_refused_via_o_nofollow() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.json");
        let key = test_key();
        store_atomic(
            &real,
            &OwnershipJournal::Preparing {
                identity: ident("m", "b", "s"),
            },
            &key,
        )
        .unwrap();
        let link = dir.path().join("nft-ownership.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = load(&link, Some(&key)).expect_err("a symlinked journal must be refused");
        assert!(matches!(err, OwnershipJournalError::UnsafeJournal { .. }));
    }

    #[test]
    fn auth_key_round_trips_and_generates_when_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-journal-auth.key");
        assert!(
            read_auth_key(&path).unwrap().is_none(),
            "absent key -> None"
        );
        let k1 = load_or_generate_auth_key(&path).unwrap();
        let k2 = read_auth_key(&path).unwrap().expect("persisted key");
        assert_eq!(k1.as_bytes(), k2.as_bytes(), "generated key persists");
    }

    #[cfg(unix)]
    #[test]
    fn a_wrong_length_key_is_unsafe() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-journal-auth.key");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        f.write_all(b"tooshort").unwrap();
        drop(f);
        let err = read_auth_key(&path).expect_err("wrong-length key must be unsafe");
        assert!(matches!(err, OwnershipJournalError::UnsafeKey { .. }));
    }

    #[test]
    fn clear_removes_the_journal_and_is_ok_when_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("j.json");
        let key = test_key();
        store_atomic(
            &path,
            &OwnershipJournal::Preparing {
                identity: ident("m", "b", "s"),
            },
            &key,
        )
        .unwrap();
        clear(&path).unwrap();
        assert!(!path.exists());
        clear(&path).unwrap(); // idempotent
    }

    #[test]
    fn clear_propagates_parent_directory_sync_failure() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("j.json");
        std::fs::write(&path, b"record").unwrap();
        let err = clear_with_parent_sync(&path, |_parent| {
            Err(std::io::Error::other("injected directory fsync failure"))
        })
        .expect_err("disarm must not report durable success after a directory sync failure");
        assert!(matches!(err, OwnershipJournalError::Durability { .. }));
        assert!(
            !path.exists(),
            "unlink happened before the failed durability check"
        );
    }

    #[test]
    fn read_boot_id_strict_trims_and_rejects_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("boot_id");
        std::fs::write(&path, "abc-123\n").unwrap();
        assert_eq!(read_boot_id_strict(&path).unwrap(), "abc-123");
        // blocker 4: empty boot id is a hard error, never an empty string.
        std::fs::write(&path, "   \n").unwrap();
        assert!(matches!(
            read_boot_id_strict(&path),
            Err(OwnershipJournalError::BootId { .. })
        ));
        // Unreadable path is a hard error too.
        assert!(matches!(
            read_boot_id_strict(&dir.path().join("nope")),
            Err(OwnershipJournalError::BootId { .. })
        ));
    }

    #[test]
    fn ct_eq_matches_only_equal_slices() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2]));
    }

    #[test]
    fn hmac_sha256_matches_a_known_answer() {
        // RFC 4231 test case 1: key = 0x0b*20, data = "Hi There".
        let key = [0x0bu8; 20];
        let tag = hmac_sha256(&key, b"Hi There");
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        assert_eq!(&tag[..], &expected[..]);
    }

    // ---- decision state machine: every crash boundary (blockers 2, 3) -------

    #[test]
    fn no_live_table_always_creates_fresh_even_with_a_stale_journal() {
        // Post-reboot: an Owned journal from a prior boot, but nft state is gone.
        let owned = OwnershipJournal::Owned {
            identity: ident("m", "old-boot", "src"),
            table_handle: 2,
            base_chain_handle: 1,
        };
        assert_eq!(
            decide(Some(&owned), false, "new-boot", "src"),
            ReclaimDecision::FreshCreate
        );
        assert_eq!(decide(None, false, "b", "s"), ReclaimDecision::FreshCreate);
    }

    #[test]
    fn no_live_table_but_owned_this_boot_re_arms_deny_all_not_fresh_accept() {
        // GF1 fault routing: the table VANISHED under a RUNNING daemon (an
        // external `nft delete table` while agents are live) -> the Owned/Preparing
        // journal is for the CURRENT boot+source but no table is present. This must
        // NOT be `FreshCreate` (which reinstalls an empty `policy accept` base with
        // no agent jumps: fail-OPEN). It routes to `ReArmLostOwned` so the caller
        // guarantees deny-all first.
        let owned_this_boot = OwnershipJournal::Owned {
            identity: ident("nonce", "boot-1", "src"),
            table_handle: 4,
            base_chain_handle: 3,
        };
        assert_eq!(
            decide(Some(&owned_this_boot), false, "boot-1", "src"),
            ReclaimDecision::ReArmLostOwned,
            "an owned table that vanished this boot must re-arm deny-all, never fresh-accept"
        );
        let preparing_this_boot = OwnershipJournal::Preparing {
            identity: ident("nonce", "boot-1", "src"),
        };
        assert_eq!(
            decide(Some(&preparing_this_boot), false, "boot-1", "src"),
            ReclaimDecision::ReArmLostOwned,
            "an interrupted acquisition whose table vanished this boot must re-arm deny-all"
        );
        // Boundary preserved: a PRIOR-boot owned record with no table is a clean
        // post-reboot start (nftables + agents both cleared), so still FreshCreate.
        let owned_prior_boot = OwnershipJournal::Owned {
            identity: ident("nonce", "OLD-boot", "src"),
            table_handle: 4,
            base_chain_handle: 3,
        };
        assert_eq!(
            decide(Some(&owned_prior_boot), false, "boot-1", "src"),
            ReclaimDecision::FreshCreate,
            "a prior-boot record with no live table is a clean fresh start, not a lost-owned re-arm"
        );
    }

    #[test]
    fn owned_journal_matching_this_boot_reclaims() {
        // The SIGKILL/TimeoutStartSec restart case the wedge fix targets: our own
        // Owned table survived the restart within the same boot -> reclaim, do
        // NOT refuse it as foreign.
        let owned = OwnershipJournal::Owned {
            identity: ident("nonce", "boot-1", "src"),
            table_handle: 4,
            base_chain_handle: 3,
        };
        assert_eq!(
            decide(Some(&owned), true, "boot-1", "src"),
            ReclaimDecision::ReclaimOwned {
                table_handle: 4,
                base_chain_handle: 3,
                marker: "nonce".to_string(),
            }
        );
    }

    #[test]
    fn preparing_journal_matching_this_boot_finalizes_the_interrupted_acquisition() {
        // Crash AFTER create but BEFORE finalize: journal is Preparing, table is
        // live. It is ours only if the marker matches; the decision says
        // "finalize with this marker", and the caller proves the marker.
        let preparing = OwnershipJournal::Preparing {
            identity: ident("nonce", "boot-1", "src"),
        };
        assert_eq!(
            decide(Some(&preparing), true, "boot-1", "src"),
            ReclaimDecision::FinalizeInterrupted {
                marker: "nonce".to_string()
            }
        );
    }

    #[test]
    fn a_live_table_with_no_journal_refuses_as_foreign_never_deletes() {
        // The classic foreign table: present, but nothing proves it is ours.
        assert_eq!(
            decide(None, true, "boot-1", "src"),
            ReclaimDecision::RefuseForeign
        );
    }

    #[test]
    fn a_journal_from_a_different_boot_or_source_does_not_authorize_reclaim() {
        let owned_other_boot = OwnershipJournal::Owned {
            identity: ident("m", "OTHER-boot", "src"),
            table_handle: 2,
            base_chain_handle: 1,
        };
        assert_eq!(
            decide(Some(&owned_other_boot), true, "boot-1", "src"),
            ReclaimDecision::RefuseForeign,
            "a prior-boot record must not authorize reclaiming a live table"
        );
        let owned_other_source = OwnershipJournal::Owned {
            identity: ident("m", "boot-1", "OTHER-binary"),
            table_handle: 2,
            base_chain_handle: 1,
        };
        assert_eq!(
            decide(Some(&owned_other_source), true, "boot-1", "src"),
            ReclaimDecision::RefuseForeign,
            "a record written by a different binary must not authorize reclaim"
        );
    }
}
