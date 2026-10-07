//! Separate daemon reservation/release log. Shipped daemon only reads existing
//! rows for stop routing; fixture write arms are absent from default builds.
use super::{
    ledger::receipt_hash,
    receipt::{self, Domain, Generation, Pins, SignedReceipt},
};
use crate::ownership_journal::{self, JournalAuthKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

pub const RELEASE_LOG_PATH: &str = "/var/lib/sanctuary/launcher/releases.log";
const MAX_ROW: usize = 16 * 1024;
const MAX_LOG: u64 = 64 * 1024 * 1024;
fn bad(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", content = "value", rename_all = "snake_case")]
pub enum Row {
    Reservation { generation: Generation, mac: String },
    Released { receipt: SignedReceipt },
    CompletionCopy { receipt: SignedReceipt },
}

#[derive(Default)]
pub struct State {
    pub reservation: Option<Generation>,
    pub released: Option<SignedReceipt>,
    pub completion: Option<SignedReceipt>,
}

fn reservation_payload(g: &Generation) -> io::Result<Vec<u8>> {
    let mut canonical = g.clone();
    canonical.reservation_hash.clear();
    serde_json::to_vec(&canonical).map_err(|_| bad("reservation serialization"))
}

pub fn reservation_hash(g: &Generation, mac: &str) -> io::Result<String> {
    let mut payload = reservation_payload(g)?;
    payload.extend_from_slice(mac.as_bytes());
    Ok(hex::encode(Sha256::digest(payload)))
}

/// Reads the journal MAC key from the path the caller named. The path is a
/// parameter and never the installed constant, because this key is the second
/// host-global name a replay touches: a caller that injects a log path but not
/// a key path still opens the operator's installed key, which is exactly the
/// installed-state read the injection boundary exists to prevent.
fn mac_key(path: &Path) -> io::Result<JournalAuthKey> {
    ownership_journal::read_auth_key(path)
        .map_err(|_| bad("journal MAC key unreadable"))?
        .ok_or_else(|| bad("journal MAC key missing"))
}

/// Replays the daemon's reservation/release log. Both names come from the
/// caller: `path` MUST MATCH the `release_log` field and `mac_key_path` the
/// `journal_mac_key` field of the `OwnerPaths` the caller is serving, in
/// `owner.rs`. Failure mode if either is read from its constant instead: the
/// module works in production and quietly reaches installed state from a test
/// run, which surfaces as an unrelated flake on whichever machine happens to
/// have Sanctuary installed.
/// `service_gid` MUST MATCH the single `getegid()` snapshot in
/// `owner::stop_failure_for_hook_at`, so all log and admission-key custody
/// checks in one hook use the group assigned to the running daemon.
pub fn replay(
    path: &Path,
    mac_key_path: &Path,
    pins: &Pins,
    service_gid: u32,
) -> io::Result<State> {
    let bytes =
        match receipt::read_custodied_file(path, 0, &[0, service_gid], 0o600, MAX_LOG as usize) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(State::default()),
            Err(e) => return Err(e),
        };
    replay_rows(&bytes, pins, || mac_key(mac_key_path))
}

fn replay_rows(
    bytes: &[u8],
    pins: &Pins,
    mut read_mac_key: impl FnMut() -> io::Result<JournalAuthKey>,
) -> io::Result<State> {
    let (admission, completion) = pins.validate().map_err(bad)?;
    let mut state = State::default();
    let mut key: Option<JournalAuthKey> = None;
    let mut reader = BufReader::new(bytes);
    let mut line = Vec::new();
    while reader.read_until(b'\n', &mut line)? != 0 {
        if line.len() > MAX_ROW || line.last() != Some(&b'\n') {
            return Err(bad("torn daemon row"));
        }
        let row: Row = serde_json::from_slice(&line[..line.len() - 1])
            .map_err(|_| bad("invalid daemon row"))?;
        if serde_json::to_vec(&row)
            .map_err(|_| bad("row encode"))?
            .as_slice()
            != &line[..line.len() - 1]
        {
            return Err(bad("noncanonical daemon row"));
        }
        match row {
            Row::Reservation { generation, mac } => {
                if state.reservation.is_some() && state.completion.is_none() {
                    return Err(bad("prior generation unresolved"));
                }
                if state.completion.is_some() {
                    state = State::default();
                }
                generation.validate().map_err(bad)?;
                // Bound rather than unwrapped: the MAC key is read at most once
                // per replay, and a replay that cannot hold it refuses the row
                // instead of panicking inside a root daemon.
                if key.is_none() {
                    key = Some(read_mac_key()?);
                }
                let Some(mac_key) = key.as_ref() else {
                    return Err(bad("journal MAC key missing"));
                };
                let payload = reservation_payload(&generation)?;
                if mac_key.reservation_mac(&payload) != mac
                    || reservation_hash(&generation, &mac)? != generation.reservation_hash
                {
                    return Err(bad("reservation MAC/hash mismatch"));
                }
                state.reservation = Some(generation);
            }
            Row::Released { receipt } => {
                receipt::verify(&receipt, Domain::ReleasedUnresolvedV1, &admission).map_err(bad)?;
                if state.reservation.as_ref() != Some(&receipt.body.generation)
                    || state.released.is_some()
                {
                    return Err(bad("unanchored release"));
                }
                state.released = Some(receipt);
            }
            Row::CompletionCopy { receipt } => {
                receipt::verify(&receipt, Domain::StopCompletionV1, &completion).map_err(bad)?;
                let old = state
                    .released
                    .as_ref()
                    .ok_or_else(|| bad("completion without release"))?;
                if state.completion.is_some()
                    || receipt.body.generation != old.body.generation
                    || receipt.body.manager != old.body.manager
                    || receipt.body.positive_extinction != Some(true)
                    || receipt.body.old_release_hash.as_ref() != Some(&receipt_hash(old)?)
                {
                    return Err(bad("completion tuple mismatch"));
                }
                state.completion = Some(receipt);
            }
        }
        line.clear();
    }
    Ok(state)
}

#[cfg(any(test, feature = "test-isolation"))]
pub fn fresh_fixture_reservation(
    mut generation: Generation,
    key: &JournalAuthKey,
) -> io::Result<(Generation, String)> {
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    generation.reservation_nonce = hex::encode(nonce);
    generation.unit_name = receipt::deterministic_unit_name(&generation);
    generation.reservation_hash.clear();
    let payload = reservation_payload(&generation)?;
    let mac = key.reservation_mac(&payload);
    generation.reservation_hash = reservation_hash(&generation, &mac)?;
    generation.validate().map_err(bad)?;
    Ok((generation, mac))
}

/// The sole production daemon-log writer is a verified owner completion copy.
/// Reservation and release writers remain fixture-only. The log path is passed
/// in rather than read from the constant so that every name this module
/// touches comes from the caller's `OwnerPaths`; `path` MUST MATCH the
/// `release_log` and `mac_key_path` the `journal_mac_key` the caller replayed,
/// since the completion is matched against that same replay. `service_gid`
/// MUST MATCH the gid passed to the surrounding `replay` calls in
/// `owner::stop_failure_for_hook_at`.
pub fn accept_completion_copy(
    path: &Path,
    mac_key_path: &Path,
    receipt: SignedReceipt,
    pins: &Pins,
    service_gid: u32,
) -> io::Result<()> {
    let (_, completion_key) = pins.validate().map_err(bad)?;
    receipt::verify(&receipt, Domain::StopCompletionV1, &completion_key).map_err(bad)?;
    let state = replay(path, mac_key_path, pins, service_gid)?;
    if let Some(old) = state.completion {
        return if old == receipt {
            Ok(())
        } else {
            Err(bad("conflicting completion reoffer"))
        };
    }
    let old = state
        .released
        .ok_or_else(|| bad("completion without local release"))?;
    if receipt.body.generation != old.body.generation
        || receipt.body.manager != old.body.manager
        || receipt.body.positive_extinction != Some(true)
        || receipt.body.old_release_hash.as_ref() != Some(&receipt_hash(&old)?)
    {
        return Err(bad("completion is not exact released tuple"));
    }
    append_checked(path, &Row::CompletionCopy { receipt }, false)
}

#[cfg(any(test, feature = "test-isolation"))]
pub fn append_fixture(path: &Path, row: &Row) -> io::Result<()> {
    append_checked(path, row, true)
}

fn append_checked(path: &Path, row: &Row, create: bool) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut bytes = serde_json::to_vec(row).map_err(|_| bad("row encode"))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_ROW {
        return Err(bad("row oversized"));
    }
    let mut file = OpenOptions::new()
        .append(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7777 != 0o600
        || meta
            .len()
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| bad("length overflow"))?
            > MAX_LOG
    {
        return Err(bad("unsafe/full daemon log"));
    }
    file.write_all(&bytes)?;
    file.sync_data()?;
    if create {
        std::fs::File::open(path.parent().ok_or_else(|| bad("daemon log parent"))?)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protected_agent::receipt::{self, ReceiptBody};
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_os = "linux")]
    #[test]
    fn replay_checks_the_supplied_service_group_against_file_custody() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("releases.log");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let service_gid = 42420;
        nix::unistd::chown(&path, None, Some(nix::unistd::Gid::from_raw(service_gid))).unwrap();

        let admission = SigningKey::from_bytes(&[3; 32]);
        let completion = SigningKey::from_bytes(&[4; 32]);
        let pins = Pins {
            schema: 1,
            algorithm: "ed25519".into(),
            admission_public: hex::encode(admission.verifying_key().as_bytes()),
            admission_key_id: receipt::key_id(&admission.verifying_key()),
            completion_public: hex::encode(completion.verifying_key().as_bytes()),
            completion_key_id: receipt::key_id(&completion.verifying_key()),
        };
        let key_path = dir.path().join("unused-key");
        assert!(replay(&path, &key_path, &pins, service_gid).is_ok());
        assert!(replay(&path, &key_path, &pins, service_gid + 1).is_err());
    }

    #[test]
    fn fixture_reservation_release_and_exact_completion_replay() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("journal-key");
        std::fs::write(&key_path, [7u8; 32]).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let key = ownership_journal::read_auth_key(&key_path)
            .unwrap()
            .unwrap();
        let admission = SigningKey::from_bytes(&[3; 32]);
        let completion = SigningKey::from_bytes(&[4; 32]);
        let pins = Pins {
            schema: 1,
            algorithm: "ed25519".into(),
            admission_public: hex::encode(admission.verifying_key().as_bytes()),
            admission_key_id: receipt::key_id(&admission.verifying_key()),
            completion_public: hex::encode(completion.verifying_key().as_bytes()),
            completion_key_id: receipt::key_id(&completion.verifying_key()),
        };
        let generation = Generation {
            boot_id: "boot".into(),
            daemon_invocation: "inv".into(),
            fortress_id: "abcdef12".into(),
            manifest_generation: "m".into(),
            ownership_generation: "o".into(),
            reservation_nonce: String::new(),
            reservation_hash: String::new(),
            account: "agent".into(),
            uid: 1001,
            gid: 1001,
            profile_id: "agent-v1".into(),
            profile_hash: "c".repeat(64),
            executable_sha256: "d".repeat(64),
            unit_name: String::new(),
        };
        let (generation, mac) = fresh_fixture_reservation(generation, &key).unwrap();
        let path = dir.path().join("releases.log");
        append_fixture(
            &path,
            &Row::Reservation {
                generation: generation.clone(),
                mac,
            },
        )
        .unwrap();
        let body = ReceiptBody {
            generation: generation.clone(),
            manager: None,
            hook: None,
            attempt_id: None,
            attempted_scope: None,
            candidate_uids: Vec::new(),
            old_release_hash: None,
            positive_extinction: None,
        };
        let release = receipt::sign(Domain::ReleasedUnresolvedV1, body, &admission).unwrap_err();
        assert_eq!(release, "invalid released row");
        let manager = crate::protected_agent::receipt::ManagerIdentity {
            unit_name: generation.unit_name.clone(),
            cgroup_path: format!("system.slice/{}", generation.unit_name),
            cgroup_dev: 1,
            cgroup_ino: 2,
            main_pid: 10,
            main_start_time: 100,
        };
        let body = ReceiptBody {
            generation: generation.clone(),
            manager: Some(manager.clone()),
            hook: None,
            attempt_id: None,
            attempted_scope: None,
            candidate_uids: Vec::new(),
            old_release_hash: None,
            positive_extinction: None,
        };
        let release = receipt::sign(Domain::ReleasedUnresolvedV1, body, &admission).unwrap();
        append_fixture(
            &path,
            &Row::Released {
                receipt: release.clone(),
            },
        )
        .unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let read_key = || {
            Ok(ownership_journal::read_auth_key(&key_path)
                .unwrap()
                .unwrap())
        };
        let state = replay_rows(&bytes, &pins, read_key).unwrap();
        assert_eq!(state.released, Some(release.clone()));
        assert!(state.completion.is_none());
        let completion_body = ReceiptBody {
            generation,
            manager: Some(manager),
            hook: None,
            attempt_id: None,
            attempted_scope: None,
            candidate_uids: Vec::new(),
            old_release_hash: Some(receipt_hash(&release).unwrap()),
            positive_extinction: Some(true),
        };
        let signed = receipt::sign(Domain::StopCompletionV1, completion_body, &completion).unwrap();
        append_fixture(
            &path,
            &Row::CompletionCopy {
                receipt: signed.clone(),
            },
        )
        .unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let state = replay_rows(&bytes, &pins, || {
            Ok(ownership_journal::read_auth_key(&key_path)
                .unwrap()
                .unwrap())
        })
        .unwrap();
        assert_eq!(state.completion, Some(signed));
        let mut altered = bytes.clone();
        let marker = b"\"mac\":\"";
        let at = altered
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap()
            + marker.len();
        altered[at] = if altered[at] == b'0' { b'1' } else { b'0' };
        assert!(replay_rows(&altered, &pins, || {
            Ok(ownership_journal::read_auth_key(&key_path)
                .unwrap()
                .unwrap())
        })
        .is_err());
        // Same log bytes, three different injected key paths, three different
        // outcomes: the key the caller names is the one a replay authenticates
        // against, so no replay can be satisfied by a key this tree does not
        // contain.
        let other_key_path = dir.path().join("other-journal-key");
        std::fs::write(&other_key_path, [9u8; 32]).unwrap();
        std::fs::set_permissions(&other_key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let absent_key_path = dir.path().join("no-journal-key-here");
        let log = std::fs::read(&path).unwrap();
        assert!(replay_rows(&log, &pins, || mac_key(&key_path)).is_ok());
        assert!(replay_rows(&log, &pins, || mac_key(&other_key_path)).is_err());
        assert!(replay_rows(&log, &pins, || mac_key(&absent_key_path)).is_err());
        assert!(!absent_key_path.exists());
    }
}
