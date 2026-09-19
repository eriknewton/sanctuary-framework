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

/// Upper bound on the on-disk authenticated envelope size.
///
/// DERIVATION from [`MAX_RECORD_BYTES`], not a chosen round number: the record is
/// base64'd, so `4 * ceil(4096 / 3)` = 5464 bytes, plus the fixed envelope keys
/// and punctuation (`mac_scheme`, `record_b64`, `mac_hex` with their quotes and
/// commas, about 60 bytes), the 14-byte scheme tag and the 64-character hex MAC:
/// 5602 bytes. Rounded up to 16 KiB so a future envelope field does not need a
/// coordinated bound change, and a file larger than this is malformed or hostile
/// and is rejected before any parse, bounding the work an attacker who can write
/// the StateDirectory could force.
const MAX_ENVELOPE_BYTES: u64 = 16 * 1024;

/// Upper bound on the decoded record bytes (the canonical `OwnershipJournal`
/// JSON).
///
/// DERIVATION over BOUNDED fields, so JSON serialisation cannot expand past it:
/// the boot id is at most [`MAX_BOOT_ID_BYTES`] of hex and hyphens, the source is
/// at most [`MAX_SOURCE_BYTES`] of printable ASCII with no quote or backslash (so
/// no character escapes to two bytes), the marker is
/// `OWNER_MARKER_PREFIX` (26) plus a 32-character hex nonce = 58 bytes, the two
/// handles and the schema version are at most 20, 20 and 10 decimal digits, and
/// the confined array is [`MAX_CONFINED_HISTORY`] entries of
/// `{"uid":4294967295,"role":"agent"}` (33 bytes) plus 15 commas and 2 brackets =
/// 545 bytes. With every fixed key, quote, colon and comma (about 150 bytes) the
/// worst case is 512 + 64 + 58 + 50 + 545 + 150 = 1379 bytes. Rounded up to 4 KiB
/// for headroom; `record_worst_case_fits_the_byte_bound` serialises the maximal
/// record and asserts it, so the derivation is checked and not just asserted.
const MAX_RECORD_BYTES: usize = 4 * 1024;

/// Largest confined-uid history one boot's journal record may carry.
///
/// DERIVATION: a signed manifest names at most one agent uid and one gate uid, so
/// 16 entries is 8 admitted identities within a single boot with no disarm. More
/// than seven identity rotations in one boot is not an operating shape this daemon
/// supports. A binding that would push the array past the cap is REFUSED, never
/// truncated: a truncated history silently drops a uid whose processes may still
/// be alive, which is the exact fail-open the array exists to close.
/// Must match `DENY_SET_MAX` in `crate::nftables`, which bounds the LIVE deny set
/// (a wider bound, because it also unions the live table's own bindings).
pub const MAX_CONFINED_HISTORY: usize = 16;

/// Longest accepted boot id, in bytes. A Linux `boot_id` is a formatted UUID (32
/// hex digits plus 4 hyphens = 36), and the non-Linux sentinel is shorter; 64
/// leaves room for a longer future form while keeping [`MAX_RECORD_BYTES`]
/// derivable. A longer value is REFUSED at read and at store, never truncated,
/// because a truncated boot id could collide with another boot's prefix and let a
/// prior-boot record authorise a reclaim.
const MAX_BOOT_ID_BYTES: usize = 64;

/// Longest accepted source (the daemon binary path), in bytes. `PATH_MAX` on
/// Linux is 4096, but a daemon installed deeper than 512 bytes is not an
/// operating shape and the bound keeps [`MAX_RECORD_BYTES`] derivable. A longer
/// path is REFUSED rather than truncated: two binaries sharing a 512-byte prefix
/// would otherwise authorise each other's reclaim.
const MAX_SOURCE_BYTES: usize = 512;

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
    /// A binding would push this boot's confined history past its cap. REFUSED,
    /// never truncated: the repair is the disarm verb, which clears the journal so
    /// the next acquisition starts a fresh history.
    #[error(
        "this boot's confined identity history is full ({count} entries, cap {cap}); \
         the array is never truncated because a dropped uid would stop being denied. \
         Stop the castle-wall unit, then run the disarm verb to clear the journal"
    )]
    ConfinedHistoryFull { count: usize, cap: usize },
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
        /// The confined identities this daemon has admitted during THIS boot,
        /// written ahead of every kernel binding, and covered by the record MAC
        /// exactly as every other field is.
        ///
        /// THREE STATES, and the distinction between the first two is
        /// essential, which is why this is an `Option` and never a bare `Vec`
        /// with a serde default:
        ///
        ///   * `None` (the key ABSENT on disk) means UNKNOWN HISTORY: the record
        ///     was written by a binary that predates this field, so neither the
        ///     manifest nor the live table can prove which uids were bound during
        ///     this boot. The safety net for such a record is host-wide.
        ///   * `Some(vec![])` means KNOWN-EMPTY: this binary wrote the record and
        ///     no identity had been bound yet.
        ///   * `Some(non-empty)` is the known history.
        ///
        /// A bare `Vec` with `#[serde(default)]` would read an ABSENT key as
        /// known-empty, which would narrow the net over a previous binary's record
        /// and let a rotated-away uid out. `skip_serializing_if` keeps `None` off
        /// the disk entirely (the key is omitted, never written as `null`), while a
        /// `Some(vec![])` IS written as `[]` because the skip never applies to a
        /// `Some`. An explicit `null` on disk also reads back as `None`.
        /// `confined_serialisation_keeps_absent_null_and_empty_distinct` pins all
        /// three forms at the byte level.
        ///
        /// Only ADMITTED identities ever enter this array (write-ahead from the
        /// manifest side). A uid observed only on the live kernel table informs the
        /// DENY set and never this record, because a `CAP_NET_ADMIN` actor can
        /// write a table but not a MAC-covered journal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confined: Option<Vec<ConfinedIdentity>>,
    },
}

/// Which confined principal a journal uid entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinedRole {
    /// The manifest's `agent_uid`.
    Agent,
    /// The manifest's optional, distinct `gate_uid`.
    Gate,
}

/// One admitted confined identity, as the journal records it.
/// Must match the `confined` array element shape in `D1b` step 1 of
/// `Review/Sanctuary/Linux_Safety_Net_Carveout_Design_2026-09-17.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinedIdentity {
    pub uid: u32,
    pub role: ConfinedRole,
}

impl OwnershipJournal {
    fn identity(&self) -> &JournalIdentity {
        match self {
            OwnershipJournal::Preparing { identity } => identity,
            OwnershipJournal::Owned { identity, .. } => identity,
        }
    }

    /// This boot's recorded confined history, or `None` for UNKNOWN HISTORY.
    ///
    /// A `Preparing` record carries no array at all and answers `None`, which is
    /// correct for a different reason than a legacy `Owned` record does: no
    /// binding has preceded it, so the caller resolves from the admitted identity.
    /// The caller distinguishes the two by the record's state, never by this value
    /// alone.
    pub fn confined(&self) -> Option<&[ConfinedIdentity]> {
        match self {
            OwnershipJournal::Preparing { .. } => None,
            OwnershipJournal::Owned { confined, .. } => confined.as_deref(),
        }
    }

    /// Build an `Owned` record with a KNOWN history (possibly empty).
    ///
    /// Refuses a history over [`MAX_CONFINED_HISTORY`] rather than truncating: a
    /// dropped entry is a uid whose processes may still be live and which the net
    /// would then never deny. The caller keeps its prior good policy on this
    /// refusal.
    pub fn owned_with_known_history(
        identity: JournalIdentity,
        table_handle: u64,
        base_chain_handle: u64,
        confined: Vec<ConfinedIdentity>,
    ) -> Result<Self, OwnershipJournalError> {
        if confined.len() > MAX_CONFINED_HISTORY {
            return Err(OwnershipJournalError::ConfinedHistoryFull {
                count: confined.len(),
                cap: MAX_CONFINED_HISTORY,
            });
        }
        Ok(OwnershipJournal::Owned {
            identity,
            table_handle,
            base_chain_handle,
            confined: Some(confined),
        })
    }

    /// Build an `Owned` record that keeps UNKNOWN HISTORY: the `confined` key is
    /// omitted from the serialised record entirely.
    ///
    /// INVARIANT (D1b step 6, state-indexed): while the key is absent on a
    /// same-boot record, NO store may materialise it. Writing `[B]` over an absent
    /// key would turn unknown history into known history on the next start and let
    /// a rotated-away uid out, so a re-store of such a record goes through here and
    /// never through [`Self::owned_with_known_history`].
    pub fn owned_with_unknown_history(
        identity: JournalIdentity,
        table_handle: u64,
        base_chain_handle: u64,
    ) -> Self {
        OwnershipJournal::Owned {
            identity,
            table_handle,
            base_chain_handle,
            confined: None,
        }
    }
}

/// PROOF that a confined uid was written durably to this boot's journal BEFORE any
/// kernel transaction bound it.
///
/// This type is the BIND row of the design's transition table, expressed so the
/// compiler enforces the order rather than a convention doing it. The per-agent
/// kernel install requires one, and the only way to obtain one is
/// [`persist_confined_uid_write_ahead`] returning `Ok`. A failed persist therefore
/// cannot reach the kernel at all: there is no value to pass.
///
/// INVARIANT on why the order is this way round: if the kernel bound a uid that the
/// journal did not yet name, a crash in between would leave a live agent whose uid no
/// later start can recover, so the safety net would never deny it. Persisting first
/// can only ever leave the journal naming MORE than the kernel does, which is the
/// safe direction: the net over-approximates and denies a uid nobody holds.
#[derive(Debug, Clone, Copy)]
pub struct WriteAheadReceipt {
    /// The uid this receipt covers, so a caller cannot present a receipt for one uid
    /// while binding another.
    uid: u32,
}

impl WriteAheadReceipt {
    /// The uid this receipt proves was persisted.
    pub fn uid(self) -> u32 {
        self.uid
    }

    /// Mint a receipt WITHOUT a journal write. Available only under the
    /// `test-isolation` feature, which the shipped build does not enable, so no
    /// production path can forge the proof.
    /// `the_write_ahead_receipt_has_no_production_mint` states the property.
    #[cfg(feature = "test-isolation")]
    pub fn for_isolated_test(uid: u32) -> Self {
        Self { uid }
    }
}

/// Persist `uid` into this boot's confined history under the caller's host lock, and
/// return the proof the kernel-side bind requires.
///
/// This is the BIND row: the persist happens FIRST and its failure is returned, so the
/// caller refuses the manifest and keeps the prior good policy with NO kernel step.
///
/// UNKNOWN HISTORY is refused rather than written: while the `confined` key is absent
/// on a same-boot record, materialising it would mark this boot's history known and a
/// uid rotated away from earlier in the boot would stop being denied. A bind cannot
/// proceed on that record, and the operator's path is the disarm verb.
pub fn persist_confined_uid_write_ahead(
    path: &Path,
    key: &JournalAuthKey,
    uid: u32,
    role: ConfinedRole,
) -> Result<WriteAheadReceipt, OwnershipJournalError> {
    persist_confined_uid_write_ahead_with_store(path, key, uid, role, store_atomic)
}

/// The injected store keeps durability failures testable at the production
/// receipt-minting boundary. No receipt is returned until store succeeds.
fn persist_confined_uid_write_ahead_with_store(
    path: &Path,
    key: &JournalAuthKey,
    uid: u32,
    role: ConfinedRole,
    store: impl FnOnce(&Path, &OwnershipJournal, &JournalAuthKey) -> Result<(), OwnershipJournalError>,
) -> Result<WriteAheadReceipt, OwnershipJournalError> {
    let record = load(path, Some(key))?;
    let Some(OwnershipJournal::Owned {
        identity,
        table_handle,
        base_chain_handle,
        confined,
    }) = record
    else {
        return Err(OwnershipJournalError::UnsafeJournal {
            path: path.to_path_buf(),
            reason: "no owned ownership record is in force, so a confined uid cannot be \
                     written ahead of a kernel binding"
                .to_string(),
        });
    };
    let Some(mut history) = confined else {
        return Err(OwnershipJournalError::UnsafeJournal {
            path: path.to_path_buf(),
            reason: "this boot's confined history is unknown, so a new binding cannot be \
                     recorded; stop the castle-wall unit, then run the disarm verb"
                .to_string(),
        });
    };
    if !history.iter().any(|entry| entry.uid == uid) {
        history.push(ConfinedIdentity { uid, role });
    }
    let next = OwnershipJournal::owned_with_known_history(
        identity,
        table_handle,
        base_chain_handle,
        history,
    )?;
    store(path, &next, key)?;
    Ok(WriteAheadReceipt { uid })
}

/// Whether `boot_id` is inside the accepted grammar: non-empty, at most
/// [`MAX_BOOT_ID_BYTES`], hexadecimal digits and hyphens only.
///
/// The grammar is checked, not just the length, because [`MAX_RECORD_BYTES`] is
/// DERIVED from these fields: a boot id carrying a quote or a control character
/// would expand under JSON escaping past the byte arithmetic the bound rests on.
fn boot_id_grammar_ok(boot_id: &str) -> bool {
    !boot_id.is_empty()
        && boot_id.len() <= MAX_BOOT_ID_BYTES
        && boot_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// Whether `source` is inside the accepted grammar: non-empty, at most
/// [`MAX_SOURCE_BYTES`], printable ASCII with no quote, backslash or control
/// character.
///
/// Same reason as [`boot_id_grammar_ok`]: a quote or backslash escapes to two
/// bytes in JSON and a control character to six, so an unvalidated source could
/// serialise past the derived record bound and produce a record the daemon cannot
/// reload.
fn source_grammar_ok(source: &str) -> bool {
    !source.is_empty()
        && source.len() <= MAX_SOURCE_BYTES
        && source.bytes().all(|b| {
            // PRINTABLE ASCII includes the space (0x20): an install path with a space in
            // it is ordinary, and `is_ascii_graphic` alone excludes it, which would
            // refuse a legitimate daemon path. Control characters, the quote and the
            // backslash stay refused, because those are what expand under JSON escaping
            // past the arithmetic MAX_RECORD_BYTES is derived over.
            (b.is_ascii_graphic() || b == b' ') && b != b'"' && b != b'\\'
        })
}

/// Validate a record's bounded identity fields. Applied at BOTH the read and the
/// store side, so the daemon can neither load nor write a record outside the
/// grammar its size bound is derived from.
fn validate_record_grammars(journal: &OwnershipJournal) -> Result<(), String> {
    let identity = journal.identity();
    if !boot_id_grammar_ok(&identity.boot_id) {
        return Err(format!(
            "boot id is outside the accepted grammar (hexadecimal digits and hyphens, \
             1 to {MAX_BOOT_ID_BYTES} bytes)"
        ));
    }
    if !source_grammar_ok(&identity.source) {
        return Err(format!(
            "source is outside the accepted grammar (printable ASCII with no quote or \
             backslash, 1 to {MAX_SOURCE_BYTES} bytes)"
        ));
    }
    if let Some(confined) = journal.confined() {
        if confined.len() > MAX_CONFINED_HISTORY {
            return Err(format!(
                "confined history carries {} entries, over the {MAX_CONFINED_HISTORY} cap",
                confined.len()
            ));
        }
    }
    Ok(())
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

    /// Separate current-boot protected-agent reservation domain. This does not
    /// change the existing key reader, first-acquisition generation, or nft
    /// journal envelope. Only the daemon holding this key can mint a reservation.
    pub fn reservation_mac(&self, canonical: &[u8]) -> String {
        let mut message = b"sanctuary.protected-agent.reservation/v1\n".to_vec();
        message.extend_from_slice(canonical);
        hex::encode(hmac_sha256(self.as_bytes(), &message))
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
    // INVARIANT: the bounded-field grammars are checked on the READ side too, not
    // only at store. An authentic record whose boot id or source is outside the
    // grammar cannot have been written by this binary, and admitting it would
    // admit a value the record-size bound is not derived over.
    if let Err(reason) = validate_record_grammars(&journal) {
        return Err(corrupt(reason));
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

    // Grammar first: refuse before any bytes are produced, so a record outside the
    // bounded-field grammar never reaches the temp file.
    if let Err(reason) = validate_record_grammars(journal) {
        return Err(OwnershipJournalError::UnsafeJournal {
            path: path.to_path_buf(),
            reason,
        });
    }
    let record_bytes = serde_json::to_vec(journal)
        .map_err(|e| mk_write(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
    // INVARIANT: measure the REAL serialised bytes, never a parallel formula. A
    // formula drifts from serde and from base64 padding, and the consequence of
    // that drift is a record the daemon writes and then cannot reload, which
    // presents at the next start as lost ownership over live agents.
    if record_bytes.len() > MAX_RECORD_BYTES {
        return Err(OwnershipJournalError::UnsafeJournal {
            path: path.to_path_buf(),
            reason: format!(
                "serialised record is {} bytes, over the {MAX_RECORD_BYTES}-byte bound the \
                 loader enforces; refusing before the rename so the journal stays readable",
                record_bytes.len()
            ),
        });
    }
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
    // Same measurement on the envelope, and again BEFORE the rename: the loader
    // refuses an envelope over this bound, so writing one would strand ownership.
    if json.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(OwnershipJournalError::UnsafeJournal {
            path: path.to_path_buf(),
            reason: format!(
                "serialised envelope is {} bytes, over the {MAX_ENVELOPE_BYTES}-byte bound the \
                 loader enforces; refusing before the rename so the journal stays readable",
                json.len()
            ),
        });
    }

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
///
/// The sentinel is deliberately inside the boot-id grammar (hexadecimal digits and
/// hyphens): the store and load sides enforce that grammar, so a sentinel outside
/// it would make every journal write on a dev host fail for a reason that has
/// nothing to do with the code under test. Must match `boot_id_grammar_ok`.
#[cfg(not(target_os = "linux"))]
pub fn current_boot_id() -> Result<String, OwnershipJournalError> {
    Ok("0de0-0000-0000-0000-000000000ded".to_string())
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
    // Same grammar the record read and store sides enforce, applied at the source:
    // a boot id that would be refused when the record is stored must be refused
    // here, where the error names the sysctl rather than the journal.
    // Must match `boot_id_grammar_ok`.
    if !boot_id_grammar_ok(&trimmed) {
        return Err(OwnershipJournalError::BootId {
            path: path.to_path_buf(),
            reason: format!(
                "boot id is outside the accepted grammar (hexadecimal digits and hyphens, \
                 1 to {MAX_BOOT_ID_BYTES} bytes)"
            ),
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
        // PIN, and the reason this routing does NOT read `confined`: the
        // never-adopt rule for a same-boot record with UNKNOWN HISTORY (the
        // `confined` key absent) is ACQUISITION-SPECIFIC and lives on the
        // acquisition path, never here. The disarm verb consumes this same shared
        // decision, and a same-boot legacy record whose live table IS the
        // recognised net must still reach disarm's `ReclaimOwned` arm to be
        // cleared. Must match the `ReclaimOwned` arm in
        // `crate::runtime_providers::disarm_castle_runtime`, which PR-2 extends to
        // clear the net from that arm.
        Some(OwnershipJournal::Owned {
            identity,
            table_handle,
            base_chain_handle,
            ..
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

    /// A boot id in the real kernel shape (a formatted UUID), which the read and
    /// store grammars accept. Fixtures that only need an OPAQUE identity for the
    /// pure `decide` routing may use any string, because `decide` never stores.
    const FIXTURE_BOOT_ID: &str = "3f2b91c0-7d4e-4a18-b6c2-0e15a9d83b77";

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
            // A REAL boot-id shape: the store and load sides both enforce the
            // hexadecimal-and-hyphen grammar the record-size bound is derived over,
            // so a fixture like "boot-1" is refused, correctly.
            identity: ident("m", FIXTURE_BOOT_ID, "/usr/local/bin/castle-wall-daemon"),
            table_handle: 2,
            base_chain_handle: 1,
            confined: Some(Vec::new()),
        };
        store_atomic(&path, &journal, &key).unwrap();
        assert_eq!(load(&path, Some(&key)).unwrap(), Some(journal));
    }

    fn store_and_reload(journal: &OwnershipJournal) -> OwnershipJournal {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        store_atomic(&path, journal, &key).expect("store");
        load(&path, Some(&key)).expect("load").expect("present")
    }

    /// The raw authenticated RECORD bytes on disk, so a test can assert on the
    /// exact serialised form rather than on what serde round-trips to.
    fn stored_record_json(journal: &OwnershipJournal) -> String {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        store_atomic(&path, journal, &key).expect("store");
        let envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("envelope");
        use base64::Engine;
        let record = base64::engine::general_purpose::STANDARD
            .decode(envelope["record_b64"].as_str().expect("record_b64"))
            .expect("decode");
        String::from_utf8(record).expect("utf8")
    }

    fn owned_fixture(confined: Option<Vec<ConfinedIdentity>>) -> OwnershipJournal {
        OwnershipJournal::Owned {
            identity: ident("m", FIXTURE_BOOT_ID, "/usr/local/bin/castle-wall-daemon"),
            table_handle: 2,
            base_chain_handle: 1,
            confined,
        }
    }

    /// The BIND row: persist succeeds, THEN bind. A failed persist yields no proof, so
    /// the kernel step is unreachable and the caller keeps its prior good policy.
    ///
    /// Inject a durability failure and crashes on either side of the journal
    /// write. A receipt exists only after the durable store returns successfully.
    #[test]
    fn the_bind_row_persists_before_the_kernel_step_and_refuses_on_a_failed_persist() {
        use std::cell::Cell;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        let identity = ident("m", FIXTURE_BOOT_ID, "/usr/local/bin/castle-wall-daemon");
        store_atomic(
            &path,
            &OwnershipJournal::Owned {
                identity,
                table_handle: 2,
                base_chain_handle: 1,
                confined: Some(Vec::new()),
            },
            &key,
        )
        .unwrap();

        // The real store completes before a bind callback can use the receipt.
        let receipt = persist_confined_uid_write_ahead(&path, &key, 60123, ConfinedRole::Agent)
            .expect("the persist must succeed on a known history");
        assert_eq!(receipt.uid(), 60123);
        let reloaded = load(&path, Some(&key)).unwrap().unwrap();
        assert_eq!(
            reloaded
                .confined()
                .map(|c| c.iter().map(|e| e.uid).collect::<Vec<_>>()),
            Some(vec![60123])
        );

        // A real error from the injected durability step mints no receipt, so
        // the kernel callback is unreachable on this path.
        let bound = Cell::new(false);
        let failed = persist_confined_uid_write_ahead_with_store(
            &path,
            &key,
            60124,
            ConfinedRole::Gate,
            |path, _, _| {
                Err(OwnershipJournalError::Durability {
                    path: path.to_path_buf(),
                    source: std::io::Error::other("injected sync failure"),
                })
            },
        );
        if let Ok(proof) = failed.as_ref() {
            bound.set(proof.uid() == 60124);
        }
        assert!(matches!(
            failed,
            Err(OwnershipJournalError::Durability { .. })
        ));
        assert!(!bound.get());
        assert_eq!(
            load(&path, Some(&key))
                .unwrap()
                .unwrap()
                .confined()
                .unwrap()
                .len(),
            1
        );

        // A crash immediately after the store returns leaves a wider durable
        // history for the next process. No kernel callback has run yet.
        let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            persist_confined_uid_write_ahead_with_store(
                &path,
                &key,
                60124,
                ConfinedRole::Gate,
                |path, record, key| {
                    store_atomic(path, record, key)?;
                    panic!("injected post-store crash");
                },
            )
        }));
        assert!(crash.is_err());
        let restarted = load(&path, Some(&key)).unwrap().unwrap();
        assert_eq!(
            restarted
                .confined()
                .unwrap()
                .iter()
                .map(|e| e.uid)
                .collect::<Vec<_>>(),
            vec![60123, 60124]
        );

        // FAILURE PATH: an UNKNOWN history refuses the persist, so no proof is minted and
        // no kernel step can follow. The prior record is left exactly as it was.
        let legacy_dir = TempDir::new().unwrap();
        let legacy_path = legacy_dir.path().join("nft-ownership.json");
        store_atomic(
            &legacy_path,
            &OwnershipJournal::owned_with_unknown_history(
                ident("m", FIXTURE_BOOT_ID, "/usr/local/bin/castle-wall-daemon"),
                2,
                1,
            ),
            &key,
        )
        .unwrap();
        let err = persist_confined_uid_write_ahead(&legacy_path, &key, 60123, ConfinedRole::Agent)
            .expect_err("an unknown history must refuse a new binding");
        assert!(
            format!("{err}").contains("disarm"),
            "the refusal names the repair: {err}"
        );
        // The record is UNCHANGED: the key is still absent, so the next start still
        // resolves this boot as unknown history.
        assert_eq!(
            load(&legacy_path, Some(&key)).unwrap().unwrap().confined(),
            None
        );

        // A persist against a missing record also refuses, so a bind cannot precede an
        // owned record at all.
        let empty_dir = TempDir::new().unwrap();
        assert!(persist_confined_uid_write_ahead(
            &empty_dir.path().join("nft-ownership.json"),
            &key,
            60123,
            ConfinedRole::Agent
        )
        .is_err());
    }

    /// CRASH AND RESTART: the rebuilt kill set equals the journal array unioned with the
    /// manifest identity.
    #[test]
    fn a_restart_rebuilds_the_kill_set_from_the_journal_unioned_with_the_manifest() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        store_atomic(
            &path,
            &OwnershipJournal::Owned {
                identity: ident("m", FIXTURE_BOOT_ID, "/usr/local/bin/castle-wall-daemon"),
                table_handle: 2,
                base_chain_handle: 1,
                confined: Some(Vec::new()),
            },
            &key,
        )
        .unwrap();
        // Two bindings persisted before their kernel steps, the second after a simulated
        // crash (we simply reload, which is what a restart does).
        persist_confined_uid_write_ahead(&path, &key, 60123, ConfinedRole::Agent).unwrap();
        persist_confined_uid_write_ahead(&path, &key, 60124, ConfinedRole::Gate).unwrap();
        // The restart reads the authenticated array and routes it through the
        // same resolver that builds the daemon's deny and kill sets.
        let rebuilt = load(&path, Some(&key))
            .unwrap()
            .unwrap()
            .confined()
            .expect("a known history")
            .to_vec();
        let resolution = crate::runtime_providers::resolve_safety_net_scope(
            &crate::runtime_providers::ConfinedHistory::Known(rebuilt),
            Some((60125, None)),
            &crate::nftables::LiveTableBindings::Bindings(vec![60126]),
            crate::safety_net_uid::HostOverflowUid::from_value(65534),
        );
        assert_eq!(
            resolution.kill_set,
            vec![60123, 60124, 60125],
            "the rebuilt kill set is the journal array unioned with the manifest identity"
        );
        assert_eq!(resolution.deny_union, vec![60123, 60124, 60125, 60126]);
        // Re-persisting an already-recorded uid is idempotent, so a retried bind after a
        // crash does not grow the array.
        persist_confined_uid_write_ahead(&path, &key, 60123, ConfinedRole::Agent).unwrap();
        assert_eq!(
            load(&path, Some(&key))
                .unwrap()
                .unwrap()
                .confined()
                .unwrap()
                .len(),
            2
        );
    }

    /// The receipt has no production mint: only a successful persist yields one, and the
    /// test-only mint is behind a feature the shipped build does not enable.
    #[test]
    fn the_write_ahead_receipt_has_no_production_mint() {
        let whole = include_str!("ownership_journal.rs");
        let source = &whole[..whole
            .find("#[cfg(test)]\nmod tests {")
            .expect("the test module ends the production half")];
        let impl_at = source
            .find("impl WriteAheadReceipt {")
            .expect("the impl block is in this file");
        let impl_end = source[impl_at..]
            .find("\n}\n")
            .map(|o| impl_at + o)
            .expect("the impl block ends");
        let block = &source[impl_at..impl_end];
        let mint_at = block
            .find("fn for_isolated_test")
            .expect("the test-only mint exists");
        assert!(
            block[..mint_at].contains("#[cfg(feature = \"test-isolation\")]"),
            "the only raw mint must be behind the test-isolation feature"
        );
        // And the struct's field is private, so no caller can build one literally.
        assert!(
            source.contains("pub struct WriteAheadReceipt {\n    /// The uid this receipt covers")
        );
        assert!(
            source.contains("pub fn persist_confined_uid_write_ahead("),
            "the persisting constructor is the production path"
        );
    }

    #[test]
    fn the_shared_routing_still_reaches_reclaim_owned_for_a_legacy_record() {
        // The never-adopt rule for an unknown-history record is ACQUISITION-SPECIFIC and
        // is applied on that path, NOT here. The disarm verb consumes this same routing,
        // and a legacy record whose live table is the recognised net must still reach the
        // `ReclaimOwned` arm so disarm can clear it. If this routing ever started
        // diverting such a record, disarm would lose its one recovery path.
        let identity = ident("m", FIXTURE_BOOT_ID, "/usr/local/bin/castle-wall-daemon");
        let legacy = OwnershipJournal::Owned {
            identity: identity.clone(),
            table_handle: 2,
            base_chain_handle: 1,
            // The key ABSENT: a record from a binary that predates the field.
            confined: None,
        };
        assert_eq!(legacy.confined(), None, "the fixture is unknown history");
        assert_eq!(
            decide(
                Some(&legacy),
                true,
                FIXTURE_BOOT_ID,
                "/usr/local/bin/castle-wall-daemon"
            ),
            ReclaimDecision::ReclaimOwned {
                table_handle: 2,
                base_chain_handle: 1,
                marker: "m".to_string(),
            },
            "the shared routing must keep disarm's arm reachable for a legacy record"
        );
        // And a CURRENT record routes identically here, so the two are distinguished by
        // the acquisition path rather than by this decision.
        let current = OwnershipJournal::Owned {
            identity,
            table_handle: 2,
            base_chain_handle: 1,
            confined: Some(Vec::new()),
        };
        assert!(matches!(
            decide(
                Some(&current),
                true,
                FIXTURE_BOOT_ID,
                "/usr/local/bin/castle-wall-daemon"
            ),
            ReclaimDecision::ReclaimOwned { .. }
        ));
    }

    #[test]
    fn confined_history_round_trips_and_the_mac_covers_it() {
        let journal = owned_fixture(Some(vec![
            ConfinedIdentity {
                uid: 60123,
                role: ConfinedRole::Agent,
            },
            ConfinedIdentity {
                uid: 60124,
                role: ConfinedRole::Gate,
            },
        ]));
        assert_eq!(store_and_reload(&journal), journal);

        // MAC COVERAGE: flipping a uid inside the array must fail authentication,
        // exactly as tampering with any other field does. If the field rode outside
        // the MAC, an actor who can write the StateDirectory could add or remove a
        // confined uid and change who the net denies.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        store_atomic(&path, &journal, &key).expect("store");
        let raw = std::fs::read_to_string(&path).expect("read");
        let mut envelope: serde_json::Value = serde_json::from_str(&raw).expect("envelope");
        use base64::Engine;
        let record = base64::engine::general_purpose::STANDARD
            .decode(envelope["record_b64"].as_str().unwrap())
            .unwrap();
        let tampered = String::from_utf8(record).unwrap().replace("60123", "60199");
        envelope["record_b64"] = serde_json::Value::String(
            base64::engine::general_purpose::STANDARD.encode(tampered.as_bytes()),
        );
        std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let err = load(&path, Some(&key)).expect_err("a tampered confined array must not load");
        assert!(
            format!("{err}").contains("MAC does not verify"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn confined_serialisation_keeps_absent_null_and_empty_distinct() {
        // `None` writes NO key. This is what makes UNKNOWN HISTORY durable: the next
        // start reads an absent key and stays host-wide.
        let absent = stored_record_json(&owned_fixture(None));
        assert!(
            !absent.contains("confined"),
            "an unknown history must omit the key entirely, never write null: {absent}"
        );
        // `Some(vec![])` writes the key as an empty array, because the
        // `skip_serializing_if` never applies to a `Some`. This is KNOWN-EMPTY.
        let empty = stored_record_json(&owned_fixture(Some(Vec::new())));
        assert!(
            empty.contains("\"confined\":[]"),
            "a known-empty history must write []: {empty}"
        );
        // And the two parse back to the two distinct states.
        assert_eq!(store_and_reload(&owned_fixture(None)).confined(), None);
        assert_eq!(
            store_and_reload(&owned_fixture(Some(Vec::new()))).confined(),
            Some(&[][..])
        );
        // An explicit `null` on disk also reads as None (unknown history), so a
        // hand-edited or previous-shape record cannot be read as known-empty.
        let record = absent.replace(
            "\"base_chain_handle\":1",
            "\"base_chain_handle\":1,\"confined\":null",
        );
        let parsed: OwnershipJournal = serde_json::from_str(&record).expect("null parses");
        assert_eq!(parsed.confined(), None);
    }

    #[test]
    fn a_previous_binary_record_reads_as_unknown_history_never_as_empty() {
        // The `Option` exists to keep these two states distinct: a record written
        // before this field existed authenticates with the key ABSENT and must read
        // as UNKNOWN history, never as a known-empty set.
        let legacy = format!(
            r#"{{"state":"owned","identity":{{"schema_version":{JOURNAL_SCHEMA_VERSION},"marker":"m","boot_id":"{FIXTURE_BOOT_ID}","source":"/usr/local/bin/castle-wall-daemon"}},"table_handle":2,"base_chain_handle":1}}"#
        );
        let parsed: OwnershipJournal = serde_json::from_str(&legacy).expect("legacy parses");
        assert_eq!(
            parsed.confined(),
            None,
            "an absent key is unknown history, never a known-empty set"
        );
        // A re-store of such a record must NOT materialise the key.
        let (identity, table_handle, base_chain_handle) = match &parsed {
            OwnershipJournal::Owned {
                identity,
                table_handle,
                base_chain_handle,
                ..
            } => (identity.clone(), *table_handle, *base_chain_handle),
            _ => panic!("owned"),
        };
        let restored =
            OwnershipJournal::owned_with_unknown_history(identity, table_handle, base_chain_handle);
        let bytes = stored_record_json(&restored);
        assert!(
            !bytes.contains("confined"),
            "re-storing an unknown history must keep the key absent: {bytes}"
        );
    }

    #[test]
    fn confined_history_is_refused_at_the_cap_plus_one_and_never_truncated() {
        let identity = ident("m", FIXTURE_BOOT_ID, "/usr/local/bin/castle-wall-daemon");
        let entries = |n: usize| {
            (0..n)
                .map(|i| ConfinedIdentity {
                    uid: 60_000 + i as u32,
                    role: if i % 2 == 0 {
                        ConfinedRole::Agent
                    } else {
                        ConfinedRole::Gate
                    },
                })
                .collect::<Vec<_>>()
        };
        // Exactly at the cap: accepted.
        let at_cap = OwnershipJournal::owned_with_known_history(
            identity.clone(),
            2,
            1,
            entries(MAX_CONFINED_HISTORY),
        )
        .expect("the cap itself is an operating shape");
        assert_eq!(
            at_cap.confined().map(|c| c.len()),
            Some(MAX_CONFINED_HISTORY)
        );
        // Cap plus one: REFUSED, and the array is not truncated to fit.
        let err = OwnershipJournal::owned_with_known_history(
            identity,
            2,
            1,
            entries(MAX_CONFINED_HISTORY + 1),
        )
        .expect_err("over the cap must refuse");
        assert!(matches!(
            err,
            OwnershipJournalError::ConfinedHistoryFull { count, cap }
                if count == MAX_CONFINED_HISTORY + 1 && cap == MAX_CONFINED_HISTORY
        ));
        assert!(
            format!("{err}").contains("disarm"),
            "the refusal must name the repair: {err}"
        );
    }

    #[test]
    fn record_worst_case_fits_the_byte_bound() {
        // The maximal grammar-valid record: the longest boot id and source the
        // grammars accept, the real marker length, `u64::MAX` handles and a full
        // ten-digit-uid history. This is what MAX_RECORD_BYTES is derived over, so
        // the derivation is CHECKED here rather than only asserted in a comment.
        let boot_id = "a".repeat(MAX_BOOT_ID_BYTES);
        let source = "/".to_string() + &"s".repeat(MAX_SOURCE_BYTES - 1);
        let marker = format!("sanctuary-castle-owner:v1:{}", "f".repeat(32));
        let confined = (0..MAX_CONFINED_HISTORY)
            .map(|i| ConfinedIdentity {
                uid: u32::MAX - i as u32,
                role: ConfinedRole::Gate,
            })
            .collect::<Vec<_>>();
        let journal = OwnershipJournal::Owned {
            identity: JournalIdentity {
                schema_version: JOURNAL_SCHEMA_VERSION,
                marker,
                boot_id,
                source,
            },
            table_handle: u64::MAX,
            base_chain_handle: u64::MAX,
            confined: Some(confined),
        };
        let bytes = serde_json::to_vec(&journal).expect("serialise");
        assert!(
            bytes.len() <= MAX_RECORD_BYTES,
            "worst-case record is {} bytes, over the {MAX_RECORD_BYTES}-byte bound",
            bytes.len()
        );
        // And it survives a real store and load, so the envelope bound holds too.
        assert_eq!(store_and_reload(&journal), journal);
    }

    #[test]
    fn store_refuses_a_record_outside_the_bounded_grammars_before_the_rename() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        // A boot id outside the hexadecimal-and-hyphen grammar.
        let bad_boot = OwnershipJournal::Owned {
            identity: ident("m", "boot-one", "/usr/local/bin/castle-wall-daemon"),
            table_handle: 2,
            base_chain_handle: 1,
            confined: Some(Vec::new()),
        };
        assert!(store_atomic(&path, &bad_boot, &key).is_err());
        // A source carrying a quote, which would escape to two bytes in JSON and
        // break the arithmetic MAX_RECORD_BYTES rests on.
        let bad_source = OwnershipJournal::Owned {
            identity: ident("m", FIXTURE_BOOT_ID, "/usr/local/bin/\"quoted\""),
            table_handle: 2,
            base_chain_handle: 1,
            confined: Some(Vec::new()),
        };
        assert!(store_atomic(&path, &bad_source, &key).is_err());
        // An over-long source.
        let long_source = OwnershipJournal::Owned {
            identity: ident("m", FIXTURE_BOOT_ID, &"s".repeat(MAX_SOURCE_BYTES + 1)),
            table_handle: 2,
            base_chain_handle: 1,
            confined: Some(Vec::new()),
        };
        assert!(store_atomic(&path, &long_source, &key).is_err());
        // FAILURE-MODE NOTE: a refused store must leave NO file behind, so the
        // prior good record (or the absence of one) still governs the next start.
        assert!(
            !path.exists(),
            "a refused store must not leave a partial journal"
        );
    }

    #[test]
    fn load_refuses_an_authentic_record_outside_the_bounded_grammars() {
        // A record whose MAC verifies but whose boot id is outside the grammar
        // cannot have been written by this binary. Admitting it would admit a value
        // the record-size bound is not derived over.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key = test_key();
        let record = format!(
            r#"{{"state":"owned","identity":{{"schema_version":{JOURNAL_SCHEMA_VERSION},"marker":"m","boot_id":"boot-one","source":"/usr/local/bin/castle-wall-daemon"}},"table_handle":2,"base_chain_handle":1,"confined":[]}}"#
        );
        let mut mac = record_mac(&key, record.as_bytes());
        use base64::Engine;
        let envelope = serde_json::json!({
            "mac_scheme": "hmac-sha256-v1",
            "record_b64": base64::engine::general_purpose::STANDARD.encode(record.as_bytes()),
            "mac_hex": hex::encode(mac),
        });
        zeroize(&mut mac);
        std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        // The loader also enforces 0600 on the journal, and a default-umask write
        // is 0644, so the fixture must set the mode the daemon itself writes.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = load(&path, Some(&key)).expect_err("grammar refusal");
        assert!(
            format!("{err}").contains("grammar"),
            "unexpected error: {err}"
        );
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
                confined: Some(Vec::new()),
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
            confined: Some(Vec::new()),
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
            confined: Some(Vec::new()),
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
            confined: Some(Vec::new()),
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
            confined: Some(Vec::new()),
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
            confined: Some(Vec::new()),
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
            confined: Some(Vec::new()),
        };
        assert_eq!(
            decide(Some(&owned_other_source), true, "boot-1", "src"),
            ReclaimDecision::RefuseForeign,
            "a record written by a different binary must not authorize reclaim"
        );
    }
}
