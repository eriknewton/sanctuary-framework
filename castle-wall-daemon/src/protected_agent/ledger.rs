//! One append-only owner ledger. Prepared and manager identity are distinct
//! fsynced class-1 rows. A missing continuation is terminal INHIBIT.
use super::receipt::{Domain, Generation, ManagerIdentity, SignedReceipt, MAX_RECEIPT_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Seek, SeekFrom, Write},
    path::Path,
};

pub const LEDGER_PATH: &str = "/var/lib/sanctuary-stop-owner/owner-ledger-v1.log";
const ACCEPTANCE_MAX: u64 = 63 * 1024 * 1024;
const TOTAL_MAX: u64 = 64 * 1024 * 1024;
const ROW_MAX: usize = 16 * 1024;
const SETTLEMENT_SLOT: u64 = ROW_MAX as u64;
const MAX_ATTEMPTS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", content = "value", rename_all = "snake_case")]
pub enum Row {
    Prepared(Generation),
    ManagerIdentity {
        unit_name: String,
        identity: ManagerIdentity,
    },
    Attempt {
        unit_name: String,
        attempt_id: String,
        command_hash: String,
        release_hash: Option<String>,
    },
    ReleaseCopy {
        unit_name: String,
        receipt: SignedReceipt,
    },
    Outcome {
        unit_name: String,
        receipt: SignedReceipt,
    },
}

impl Row {
    fn acceptance(&self) -> bool {
        matches!(
            self,
            Self::Prepared(_) | Self::ManagerIdentity { .. } | Self::Attempt { .. }
        )
    }
    fn unit_name(&self) -> &str {
        match self {
            Self::Prepared(g) => &g.unit_name,
            Self::ManagerIdentity { unit_name, .. }
            | Self::Attempt { unit_name, .. }
            | Self::ReleaseCopy { unit_name, .. }
            | Self::Outcome { unit_name, .. } => unit_name,
        }
    }
}

/// Named states of the two-row CREATE transaction. Prepared and the manager
/// identity are separate fsynced rows of ONE transaction, so the window in
/// which identity may follow Prepared has to be a state, not an absence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CreateTransaction {
    /// No CREATE transaction is open in this handle. Every replayed Prepared
    /// row is in this state: a process that finds a Prepared row it did not
    /// itself write cannot know whether the CREATE that wrote it ever
    /// completed, so identity may never follow it retrospectively, and the
    /// record stays terminal Prepared and INHIBIT.
    #[default]
    Sealed,
    /// This handle appended the Prepared row for `unit_name` and has not left
    /// that transaction, so the manager identity may still follow it.
    Open { unit_name: String },
}

#[derive(Clone, Debug, Default)]
pub struct GenerationState {
    pub prepared: Option<Generation>,
    pub manager: Option<ManagerIdentity>,
    pub attempts: BTreeMap<String, (String, Option<String>)>,
    pub release: Option<SignedReceipt>,
    pub outcome: Option<SignedReceipt>,
}
impl GenerationState {
    pub fn is_open(&self) -> bool {
        self.prepared.is_some() && self.outcome.is_none()
    }
}

#[derive(Clone, Debug, Default)]
pub struct LedgerState {
    pub generations: BTreeMap<String, GenerationState>,
    pub bytes: u64,
    /// Which CREATE transaction, if any, this handle itself opened. Replay
    /// leaves it `Sealed`, which is what makes a crash between the Prepared row
    /// and the identity row terminal rather than resumable.
    pub create_transaction: CreateTransaction,
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn checked_capacity(
    current: u64,
    row_bytes: u64,
    acceptance: bool,
    owed_slots: u64,
) -> io::Result<u64> {
    let after = current
        .checked_add(row_bytes)
        .ok_or_else(|| invalid("ledger overflow"))?;
    if after
        > if acceptance {
            ACCEPTANCE_MAX
        } else {
            TOTAL_MAX
        }
    {
        return Err(invalid("ledger class ceiling"));
    }
    if after
        .checked_add(owed_slots)
        .ok_or_else(|| invalid("settlement overflow"))?
        > TOTAL_MAX
    {
        return Err(invalid("settlement slots"));
    }
    Ok(after)
}

fn apply(state: &mut LedgerState, row: &Row) -> io::Result<()> {
    let unit = row.unit_name();
    match row {
        Row::Prepared(g) => {
            g.validate().map_err(invalid)?;
            if state.generations.values().any(GenerationState::is_open)
                || state.generations.contains_key(unit)
            {
                return Err(invalid("multiple open generations or reused unit"));
            }
            state.generations.insert(
                unit.to_owned(),
                GenerationState {
                    prepared: Some(g.clone()),
                    ..Default::default()
                },
            );
            // Applying a Prepared row is what opens the CREATE transaction.
            // Replay closes it again once the whole file has been read, so only
            // the handle that actually wrote this row is inside the window.
            state.create_transaction = CreateTransaction::Open {
                unit_name: unit.to_owned(),
            };
        }
        Row::ManagerIdentity { identity, .. } => {
            // Identity may follow Prepared ONLY inside the transaction that
            // wrote that Prepared row. Without this, a handle that reopened the
            // ledger after a crash could append the missing identity and revive
            // a record whose CREATE never completed, which is exactly the state
            // the two-row split exists to make terminal.
            if state.create_transaction
                != (CreateTransaction::Open {
                    unit_name: unit.to_owned(),
                })
            {
                return Err(invalid("identity outside the CREATE transaction"));
            }
            let entry = state
                .generations
                .get_mut(unit)
                .ok_or_else(|| invalid("manager without Prepared"))?;
            let Some(prepared) = entry.prepared.as_ref() else {
                return Err(invalid("manager without Prepared"));
            };
            if !entry.is_open() || entry.manager.is_some() {
                return Err(invalid("duplicate manager identity"));
            }
            identity.validate(prepared).map_err(invalid)?;
            entry.manager = Some(identity.clone());
            // The two-row transaction is complete; nothing further may be
            // appended to this record under CREATE authority.
            state.create_transaction = CreateTransaction::Sealed;
        }
        Row::Attempt {
            attempt_id,
            command_hash,
            release_hash,
            ..
        } => {
            let entry = state
                .generations
                .get_mut(unit)
                .ok_or_else(|| invalid("attempt without Prepared"))?;
            if !entry.is_open()
                || entry.manager.is_none()
                || entry.attempts.len() >= MAX_ATTEMPTS
                || entry.attempts.contains_key(attempt_id)
                || attempt_id.is_empty()
                || command_hash.len() != 64
                || !command_hash.bytes().all(|c| c.is_ascii_hexdigit())
            {
                return Err(invalid("invalid attempt"));
            }
            if entry.release.as_ref().map(receipt_hash).transpose()? != *release_hash {
                return Err(invalid("attempt release mismatch"));
            }
            entry.attempts.insert(
                attempt_id.clone(),
                (command_hash.clone(), release_hash.clone()),
            );
        }
        Row::ReleaseCopy { receipt, .. } => {
            let entry = state
                .generations
                .get_mut(unit)
                .ok_or_else(|| invalid("release without Prepared"))?;
            // Bound rather than unwrapped: `is_open()` implies a Prepared row
            // today, but a row class that reaches this arm without one must
            // refuse, never panic in a root daemon.
            let Some(prepared) = entry.prepared.clone() else {
                return Err(invalid("release without Prepared"));
            };
            if !entry.is_open()
                || entry.manager.is_none()
                || entry.release.is_some()
                || entry.attempts.values().any(|(_, old)| old.is_none())
                || receipt.domain != Domain::ReleasedUnresolvedV1
                || receipt.body.generation != prepared
                || receipt.body.manager.as_ref() != entry.manager.as_ref()
            {
                return Err(invalid("release identity mismatch"));
            }
            entry.release = Some(receipt.clone());
        }
        Row::Outcome { receipt, .. } => {
            let entry = state
                .generations
                .get_mut(unit)
                .ok_or_else(|| invalid("outcome without Prepared"))?;
            // Same reason as the release arm: refuse an outcome whose anchor is
            // missing instead of panicking on it.
            let Some(prepared) = entry.prepared.clone() else {
                return Err(invalid("outcome without Prepared"));
            };
            if !entry.is_open()
                || entry.manager.is_none()
                || entry.outcome.is_some()
                || receipt.body.positive_extinction != Some(true)
                || receipt.body.generation != prepared
                || receipt.body.manager.as_ref() != entry.manager.as_ref()
            {
                return Err(invalid("outcome identity mismatch"));
            }
            let expected = if entry.release.is_some() {
                Domain::StopCompletionV1
            } else {
                Domain::PreparedExtinctionV1
            };
            if receipt.domain != expected
                || (expected == Domain::StopCompletionV1
                    && receipt.body.old_release_hash
                        != entry.release.as_ref().map(receipt_hash).transpose()?)
            {
                return Err(invalid("outcome scope mismatch"));
            }
            entry.outcome = Some(receipt.clone());
        }
    }
    Ok(())
}

pub fn receipt_hash(r: &SignedReceipt) -> io::Result<String> {
    let bytes = serde_json::to_vec(r).map_err(|_| invalid("receipt serialization"))?;
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(invalid("receipt oversized"));
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub struct Ledger {
    file: File,
    pub state: LedgerState,
    uncertain: bool,
}
impl Ledger {
    pub fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawFd,
        };
        let mut opts = OpenOptions::new();
        opts.read(true).append(true).create(true);
        #[cfg(unix)]
        opts.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = opts.open(path)?;
        #[cfg(unix)]
        {
            let m = file.metadata()?;
            if !m.is_file()
                || m.nlink() != 1
                || m.uid() != unsafe { libc::geteuid() }
                || (m.mode() & 0o7777) != 0o600
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe owner ledger custody",
                ));
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let state = Self::replay(&mut file)?;
        File::open(path.parent().ok_or_else(|| invalid("ledger parent"))?)?.sync_all()?;
        Ok(Self {
            file,
            state,
            uncertain: false,
        })
    }

    /// Recheck all retained signed evidence against installed immutable pins
    /// before owner READY. Missing/rotated pins with open rows refuse startup.
    pub fn validate_signatures(&self, pins: &super::receipt::Pins) -> io::Result<()> {
        let (admission, completion) = pins.validate().map_err(invalid)?;
        for entry in self.state.generations.values() {
            if let Some(release) = &entry.release {
                super::receipt::verify(release, Domain::ReleasedUnresolvedV1, &admission)
                    .map_err(invalid)?;
            }
            if let Some(outcome) = &entry.outcome {
                super::receipt::verify(outcome, outcome.domain, &completion).map_err(invalid)?;
                if !matches!(
                    outcome.domain,
                    Domain::StopCompletionV1 | Domain::PreparedExtinctionV1
                ) {
                    return Err(invalid("wrong owner outcome domain"));
                }
            }
        }
        Ok(())
    }

    fn replay(file: &mut File) -> io::Result<LedgerState> {
        let len = file.metadata()?.len();
        if len > TOTAL_MAX {
            return Err(invalid("ledger exceeds 64 MiB"));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut reader = BufReader::new(&mut *file);
        let mut state = LedgerState::default();
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line)? != 0 {
            if line.len() > ROW_MAX || line.last() != Some(&b'\n') {
                return Err(invalid("torn or oversized row"));
            }
            let row: Row = serde_json::from_slice(&line[..line.len() - 1])
                .map_err(|_| invalid("invalid ledger row"))?;
            let canonical = serde_json::to_vec(&row).map_err(|_| invalid("row serialization"))?;
            if canonical.as_slice() != &line[..line.len() - 1] {
                return Err(invalid("noncanonical ledger row"));
            }
            let after = state
                .bytes
                .checked_add(line.len() as u64)
                .ok_or_else(|| invalid("ledger overflow"))?;
            if after
                > if row.acceptance() {
                    ACCEPTANCE_MAX
                } else {
                    TOTAL_MAX
                }
            {
                return Err(invalid("row exceeds class ceiling"));
            }
            apply(&mut state, &row)?;
            state.bytes = after;
            line.clear();
        }
        if state.bytes != len {
            return Err(invalid("ledger length changed"));
        }
        // Leaving replay ends every CREATE transaction the file records. A
        // Prepared row without its identity row is now terminal: the process
        // that could have completed it is gone, and no later handle may append
        // the identity it was missing.
        state.create_transaction = CreateTransaction::Sealed;
        file.seek(SeekFrom::End(0))?;
        Ok(state)
    }

    fn append(&mut self, row: Row) -> io::Result<()> {
        if self.uncertain {
            return Err(invalid("ledger durability uncertain"));
        }
        let mut bytes = serde_json::to_vec(&row).map_err(|_| invalid("row serialization"))?;
        bytes.push(b'\n');
        if bytes.len() > ROW_MAX {
            return Err(invalid("row exceeds 16 KiB"));
        }
        let mut candidate = self.state.clone();
        apply(&mut candidate, &row)?;
        let owed =
            if row.acceptance() && candidate.generations.values().any(GenerationState::is_open) {
                if candidate
                    .generations
                    .values()
                    .any(|s| s.is_open() && s.release.is_some())
                {
                    SETTLEMENT_SLOT
                } else {
                    2 * SETTLEMENT_SLOT
                }
            } else {
                0
            };
        let after = checked_capacity(self.state.bytes, bytes.len() as u64, row.acceptance(), owed)?;
        if self.file.metadata()?.len() != self.state.bytes {
            return Err(invalid("ledger changed externally"));
        }
        self.uncertain = true;
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;
        candidate.bytes = after;
        self.state = candidate;
        self.uncertain = false;
        Ok(())
    }

    /// Fixture-only CREATE anchor. Shipped owner has no caller for this arm.
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn prepare_fixture(&mut self, g: Generation) -> io::Result<()> {
        let projected = self
            .state
            .bytes
            .checked_add(4 * SETTLEMENT_SLOT)
            .ok_or_else(|| invalid("capacity overflow"))?;
        if projected > TOTAL_MAX || self.state.bytes + 2 * SETTLEMENT_SLOT > ACCEPTANCE_MAX {
            return Err(invalid("no continuation capacity"));
        }
        self.append(Row::Prepared(g))
    }
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn manager_created_fixture(
        &mut self,
        unit_name: String,
        identity: ManagerIdentity,
    ) -> io::Result<()> {
        self.append(Row::ManagerIdentity {
            unit_name,
            identity,
        })
    }

    /// Reproduces the state a failed row write or failed fsync leaves behind:
    /// an append was attempted and this handle cannot say whether it landed.
    /// It exists so the durability gate can be shown to refuse in that state,
    /// and it can only ever make the ledger more refusing.
    #[cfg(test)]
    fn mark_durability_uncertain(&mut self) {
        self.uncertain = true;
    }

    /// The pre-release durability gate. Its caller treats a success as proof
    /// that the anchor rows are on disk, so it must refuse in every state where
    /// this handle cannot say that: after a write or fsync whose outcome is
    /// unknown, and whenever the file's length no longer agrees with the bytes
    /// the replayed rows account for. Failure mode if either check is skipped:
    /// the ACK reads exactly like a durable one, and the caller proceeds past a
    /// gate whose anchor may never have reached the disk.
    pub fn prepared_ack(&self, g: &Generation, m: &ManagerIdentity) -> io::Result<()> {
        if self.uncertain {
            return Err(invalid("ledger durability uncertain"));
        }
        if self.file.metadata()?.len() != self.state.bytes {
            return Err(invalid("ledger changed externally"));
        }
        let entry = self
            .state
            .generations
            .get(&g.unit_name)
            .ok_or_else(|| invalid("no Prepared anchor"))?;
        if !entry.is_open()
            || entry.prepared.as_ref() != Some(g)
            || entry.manager.as_ref() != Some(m)
            || self
                .state
                .bytes
                .checked_add(2 * SETTLEMENT_SLOT)
                .ok_or_else(|| invalid("capacity overflow"))?
                > TOTAL_MAX
        {
            return Err(invalid("Prepared/manager/capacity mismatch"));
        }
        Ok(())
    }

    pub fn accept_attempt(
        &mut self,
        unit: &str,
        id: &str,
        hash: &str,
        release_hash: Option<&str>,
    ) -> io::Result<()> {
        let e = self
            .state
            .generations
            .get(unit)
            .ok_or_else(|| invalid("no owned generation"))?;
        if let Some((old_hash, old_release)) = e.attempts.get(id) {
            return if old_hash == hash && old_release.as_deref() == release_hash {
                Ok(())
            } else {
                Err(invalid("conflicting attempt retry"))
            };
        }
        if e.attempts.len() >= MAX_ATTEMPTS {
            return Err(invalid("64 attempt limit"));
        }
        self.append(Row::Attempt {
            unit_name: unit.into(),
            attempt_id: id.into(),
            command_hash: hash.into(),
            release_hash: release_hash.map(str::to_owned),
        })
    }

    pub fn accept_release_copy(&mut self, receipt: SignedReceipt) -> io::Result<()> {
        let unit = &receipt.body.generation.unit_name;
        if let Some(e) = self.state.generations.get(unit) {
            if let Some(old) = &e.release {
                return if old == &receipt {
                    Ok(())
                } else {
                    Err(invalid("conflicting release copy"))
                };
            }
        }
        self.append(Row::ReleaseCopy {
            unit_name: unit.clone(),
            receipt,
        })
    }

    pub fn record_outcome(&mut self, receipt: SignedReceipt) -> io::Result<()> {
        let unit = &receipt.body.generation.unit_name;
        if let Some(e) = self.state.generations.get(unit) {
            if let Some(old) = &e.outcome {
                return if old == &receipt {
                    Ok(())
                } else {
                    Err(invalid("conflicting outcome"))
                };
            }
        }
        self.append(Row::Outcome {
            unit_name: unit.clone(),
            receipt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protected_agent::receipt::{deterministic_unit_name, ReceiptBody};
    use ed25519_dalek::SigningKey;
    fn fixture() -> (Generation, ManagerIdentity) {
        let mut g = Generation {
            boot_id: "boot".into(),
            daemon_invocation: "inv".into(),
            fortress_id: "abcdef12".into(),
            manifest_generation: "m".into(),
            ownership_generation: "o".into(),
            reservation_nonce: "a".repeat(64),
            reservation_hash: "b".repeat(64),
            account: "agent".into(),
            uid: 1001,
            gid: 1001,
            profile_id: "agent-v1".into(),
            profile_hash: "c".repeat(64),
            executable_sha256: "d".repeat(64),
            unit_name: String::new(),
        };
        g.unit_name = deterministic_unit_name(&g);
        let m = ManagerIdentity {
            unit_name: g.unit_name.clone(),
            cgroup_path: format!("system.slice/{}", g.unit_name),
            cgroup_dev: 1,
            cgroup_ino: 2,
            main_pid: 10,
            main_start_time: 100,
        };
        (g, m)
    }
    #[test]
    fn prepared_never_clears_by_absence_and_identity_never_follows_a_replayed_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger");
        let (g, m) = fixture();
        let mut l = Ledger::open(&path).unwrap();
        l.prepare_fixture(g.clone()).unwrap();
        assert!(l.prepared_ack(&g, &m).is_err());
        drop(l);
        // The anchor survives the reopen, and stays open...
        let mut l = Ledger::open(&path).unwrap();
        assert!(l.state.generations[&g.unit_name].is_open());
        // ...but the CREATE transaction that could have completed it is over,
        // so the record is terminal Prepared rather than resumable.
        assert!(l
            .manager_created_fixture(g.unit_name.clone(), m.clone())
            .is_err());
        assert!(l.prepared_ack(&g, &m).is_err());
        drop(l);
        let l = Ledger::open(&path).unwrap();
        assert!(l.state.generations[&g.unit_name].manager.is_none());
        assert!(l.prepared_ack(&g, &m).is_err());
    }

    #[test]
    fn a_ledger_that_cannot_vouch_for_its_own_bytes_refuses_the_prepared_ack() {
        let dir = tempfile::tempdir().unwrap();
        let (g, m) = fixture();

        let uncertain_path = dir.path().join("uncertain-ledger");
        let mut l = Ledger::open(&uncertain_path).unwrap();
        l.prepare_fixture(g.clone()).unwrap();
        l.manager_created_fixture(g.unit_name.clone(), m.clone())
            .unwrap();
        l.prepared_ack(&g, &m).unwrap();
        // After an append whose durability is unknown, the anchor rows may or
        // may not be on disk, so the gate must refuse rather than report the
        // state it replayed before the failure.
        l.mark_durability_uncertain();
        assert!(l.prepared_ack(&g, &m).is_err());
        drop(l);

        let grown_path = dir.path().join("grown-ledger");
        let mut l = Ledger::open(&grown_path).unwrap();
        l.prepare_fixture(g.clone()).unwrap();
        l.manager_created_fixture(g.unit_name.clone(), m.clone())
            .unwrap();
        l.prepared_ack(&g, &m).unwrap();
        // Bytes this handle never accounted for mean the replayed state is no
        // longer a description of the file.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&grown_path)
            .unwrap()
            .write_all(b"{}\n")
            .unwrap();
        assert!(l.prepared_ack(&g, &m).is_err());
    }

    #[test]
    fn retries_are_exact_and_accepted_attempts_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger");
        let (g, m) = fixture();
        let mut l = Ledger::open(&path).unwrap();
        l.prepare_fixture(g.clone()).unwrap();
        l.manager_created_fixture(g.unit_name.clone(), m.clone())
            .unwrap();
        l.prepared_ack(&g, &m).unwrap();
        let body = ReceiptBody {
            generation: g.clone(),
            manager: Some(m.clone()),
            hook: None,
            attempt_id: None,
            attempted_scope: None,
            candidate_uids: Vec::new(),
            old_release_hash: None,
            positive_extinction: None,
        };
        let key = SigningKey::from_bytes(&[3; 32]);
        let release =
            crate::protected_agent::receipt::sign(Domain::ReleasedUnresolvedV1, body, &key)
                .unwrap();
        l.accept_release_copy(release.clone()).unwrap();
        let hash = receipt_hash(&release).unwrap();
        l.accept_attempt(&g.unit_name, "a", "f".repeat(64).as_str(), Some(&hash))
            .unwrap();
        l.accept_attempt(&g.unit_name, "a", "f".repeat(64).as_str(), Some(&hash))
            .unwrap();
        assert!(l
            .accept_attempt(&g.unit_name, "a", "e".repeat(64).as_str(), Some(&hash))
            .is_err());
        drop(l);
        let l = Ledger::open(&path).unwrap();
        assert!(l.state.generations[&g.unit_name].is_open());
        assert_eq!(l.state.generations[&g.unit_name].attempts.len(), 1);
    }

    #[test]
    fn sixty_four_ids_refuse_new_ack_but_keep_two_settlement_rows_available() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger");
        let (g, m) = fixture();
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut l = Ledger::open(&path).unwrap();
        l.prepare_fixture(g.clone()).unwrap();
        l.manager_created_fixture(g.unit_name.clone(), m.clone())
            .unwrap();
        l.prepared_ack(&g, &m).unwrap();
        let body = ReceiptBody {
            generation: g.clone(),
            manager: Some(m.clone()),
            hook: None,
            attempt_id: None,
            attempted_scope: None,
            candidate_uids: Vec::new(),
            old_release_hash: None,
            positive_extinction: None,
        };
        let release =
            crate::protected_agent::receipt::sign(Domain::ReleasedUnresolvedV1, body, &key)
                .unwrap();
        l.accept_release_copy(release.clone()).unwrap();
        let old = receipt_hash(&release).unwrap();
        for n in 0..64 {
            l.accept_attempt(
                &g.unit_name,
                &format!("{n:02}"),
                &"a".repeat(64),
                Some(&old),
            )
            .unwrap();
        }
        let size_before = l.state.bytes;
        assert!(l
            .accept_attempt(&g.unit_name, "64", &"a".repeat(64), Some(&old))
            .is_err());
        assert_eq!(l.state.bytes, size_before);
        l.accept_attempt(&g.unit_name, "00", &"a".repeat(64), Some(&old))
            .unwrap();
        assert_eq!(l.state.bytes, size_before);
        let completion_body = ReceiptBody {
            generation: g.clone(),
            manager: Some(m),
            hook: None,
            attempt_id: None,
            attempted_scope: None,
            candidate_uids: Vec::new(),
            old_release_hash: Some(old),
            positive_extinction: Some(true),
        };
        let completion =
            crate::protected_agent::receipt::sign(Domain::StopCompletionV1, completion_body, &key)
                .unwrap();
        l.record_outcome(completion.clone()).unwrap();
        drop(l);
        let l = Ledger::open(&path).unwrap();
        assert!(!l.state.generations[&g.unit_name].is_open());
        assert_eq!(l.state.generations[&g.unit_name].outcome, Some(completion));
    }
    #[test]
    fn total_byte_ceiling_preserves_settlement_capacity() {
        assert_eq!(
            checked_capacity(ACCEPTANCE_MAX - 1, 1, true, 2 * SETTLEMENT_SLOT).unwrap(),
            ACCEPTANCE_MAX
        );
        assert!(checked_capacity(ACCEPTANCE_MAX, 1, true, 2 * SETTLEMENT_SLOT).is_err());
        assert_eq!(
            checked_capacity(TOTAL_MAX - 1, 1, false, 0).unwrap(),
            TOTAL_MAX
        );
        assert!(checked_capacity(TOTAL_MAX, 1, false, 0).is_err());
    }
}
