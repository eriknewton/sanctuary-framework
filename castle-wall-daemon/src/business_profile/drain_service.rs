//! Independent drain composition; no production caller grants signing authority here.
use super::{
    custody, drain_protocol as protocol,
    drain_store::Authority,
    signer_peer,
    writer_peer::{self, BusTarget, Deadline, DropIn, WallMainBinding, WallPolicy},
};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::RawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Refusal {
    CONFIG,
    CLASSIFY,
    BIND,
    DEADLINE,
    ROLE,
    AUTHORITY,
    RECONCILE,
    RETRY,
    PROPOSE,
    ENVELOPE,
    BODY_DIGEST,
    CHAIN,
    DESCRIPTOR,
    KID,
    GRANT,
    SIGNATURE,
    COMMITMENT,
    CAPACITY,
    STORE,
    REVALIDATE,
    REPLY,
    ROOT,
    SOCKET,
}
pub type Result<T> = std::result::Result<T, Refusal>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WallConfig {
    pub unit: String,
    pub exec: PathBuf,
    pub sha256: String,
    pub argv_sha256: String,
    pub unit_sha256: String,
    pub dropins: Vec<DropIn>,
    pub gid: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainConfig {
    pub version: u8,
    pub fortress_id: String,
    pub signer: signer_peer::PeerPolicy,
    pub wall: WallConfig,
}
impl DrainConfig {
    pub fn wall_policy(&self) -> WallPolicy<'_> {
        WallPolicy {
            wall_unit: &self.wall.unit,
            wall_exec: &self.wall.exec,
            wall_sha256: &self.wall.sha256,
            wall_argv_sha256: &self.wall.argv_sha256,
            wall_unit_sha256: &self.wall.unit_sha256,
            wall_dropins: &self.wall.dropins,
            wall_gid: self.wall.gid,
        }
    }
}
pub struct HeldConfig {
    pub value: DrainConfig,
    _file: File,
}
fn pin(s: &str) -> bool {
    s.len() == super::activation_anchor::DIGEST_HEX_LENGTH
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl HeldConfig {
    pub fn production() -> Result<Self> {
        Self::load(
            Path::new(crate::config::BUSINESS_DRAIN_CONFIG),
            custody::ROOT_UID,
            true,
        )
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(path: &Path, owner: u32) -> Result<Self> {
        Self::load(path, owner, false)
    }
    fn load(path: &Path, owner: u32, production: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| Refusal::CONFIG)?;
        let m = file.metadata().map_err(|_| Refusal::CONFIG)?;
        if !m.is_file()
            || m.uid() != owner
            || m.mode() & 0o7777 != custody::PRIVATE_MODE
            || m.nlink() != 1
            || m.len() > custody::CONFIG_MAX_BYTES as u64
        {
            return Err(Refusal::CONFIG);
        }
        let mut bytes = Vec::new();
        (&file)
            .take(custody::CONFIG_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Refusal::CONFIG)?;
        let v =
            protocol::canonical(&bytes, custody::CONFIG_MAX_BYTES).map_err(|_| Refusal::CONFIG)?;
        let value: DrainConfig = serde_json::from_value(v).map_err(|_| Refusal::CONFIG)?;
        if value.version != 1
            || !protocol::id(&value.fortress_id)
            || value.wall.unit.is_empty()
            || !value.wall.exec.is_absolute()
            || value.wall.dropins.len() > writer_peer::WALL_DROPINS_MAX
            || [
                &value.wall.sha256,
                &value.wall.argv_sha256,
                &value.wall.unit_sha256,
                &value.signer.executable_sha256,
            ]
            .iter()
            .any(|s| !pin(s))
            || (production
                && (value.wall.unit != writer_peer::WALL_UNIT
                    || value.wall.exec != Path::new(writer_peer::WALL_EXEC)))
        {
            return Err(Refusal::CONFIG);
        }
        let mut paths = BTreeSet::new();
        for d in &value.wall.dropins {
            if !d.path.is_absolute() || !pin(&d.sha256) || !paths.insert(&d.path) {
                return Err(Refusal::CONFIG);
            }
        }
        Ok(Self { value, _file: file })
    }
}
/// Classification is only a partition; each branch still captures kernel credentials and pidfds.
pub struct Classifier {
    #[cfg(feature = "test-isolation")]
    signer_pid: Option<i32>,
}
impl Classifier {
    pub fn production() -> Self {
        Self {
            #[cfg(feature = "test-isolation")]
            signer_pid: None,
        }
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(signer_pid: i32) -> Self {
        Self {
            signer_pid: Some(signer_pid),
        }
    }
    fn signer(&self, pid: i32, actual: &str, configured: &str) -> bool {
        #[cfg(feature = "test-isolation")]
        if let Some(signer) = self.signer_pid {
            return signer == pid;
        }
        let _ = pid;
        actual == configured
    }
}
pub enum Binding {
    S(signer_peer::Peer),
    W(WallMainBinding),
}
impl Binding {
    pub fn authority(&self) -> Authority {
        match self {
            Self::S(_) => Authority::S,
            Self::W(_) => Authority::W,
        }
    }
    pub fn capture(
        fd: RawFd,
        config: &DrainConfig,
        bus: &BusTarget,
        peer_uid: u32,
        owner: u32,
        classifier: &Classifier,
        end: Deadline,
    ) -> Result<Self> {
        end.check().map_err(|_| Refusal::DEADLINE)?;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as _,
                &mut len,
            )
        } != 0
            || len as usize != std::mem::size_of_val(&cred)
            || cred.pid <= 0
        {
            return Err(Refusal::CLASSIFY);
        }
        let raw = writer_peer::read_proc(Path::new(&format!("/proc/{}/cgroup", cred.pid)))
            .map_err(|_| Refusal::CLASSIFY)?;
        let actual = writer_peer::normalized_cgroup(&raw).map_err(|_| Refusal::CLASSIFY)?;
        let configured =
            writer_peer::normalized_cgroup(&config.signer.cgroup).map_err(|_| Refusal::CLASSIFY)?;
        let binding = if classifier.signer(cred.pid, &actual, &configured) {
            // A failed signer capture never falls back to wall authority or consults the wall bus.
            Self::S(signer_peer::Peer::capture(fd, &config.signer).map_err(|_| Refusal::CLASSIFY)?)
        } else {
            // The supplementary group narrows who can connect, but it is not a bound against a uid 0 peer; the MainPID equality is that bound.
            // Shared capture binds ControlGroup to this actual peer cgroup; the production partition excludes signer overlap.
            Self::W(
                WallMainBinding::capture(
                    fd,
                    &config.wall_policy(),
                    bus,
                    peer_uid,
                    owner,
                    end.clone(),
                )
                .map_err(|_| Refusal::CLASSIFY)?,
            )
        };
        end.check().map_err(|_| Refusal::DEADLINE)?;
        Ok(binding)
    }
    pub fn packet(&self, p: &signer_peer::Packet) -> Result<()> {
        if !p.rights.is_empty() {
            return Err(Refusal::BIND);
        }
        let valid = match self {
            Self::S(s) => s.matches(p),
            Self::W(w) => w.packet(p).is_ok(),
        };
        if valid {
            Ok(())
        } else {
            Err(Refusal::BIND)
        }
    }
    pub fn revalidate(&self, bus: &BusTarget, end: Deadline) -> Result<()> {
        end.check().map_err(|_| Refusal::DEADLINE)?;
        let valid = match self {
            Self::S(s) => s.live(),
            Self::W(w) => w.revalidate(bus, end.clone()).is_ok() && w.live(),
        };
        if !valid {
            return Err(Refusal::REVALIDATE);
        }
        end.check().map_err(|_| Refusal::DEADLINE)
    }
}
/// The wall can only extend record history and the signer can only change custody and grant identity; neither can perform the other's transition.
pub fn authorized(authority: Authority, phase: super::drain_store::Phase) -> bool {
    Authority::for_phase(phase) == authority
}

#[cfg(test)]
mod component_tests {
    use super::super::drain_store::Phase;
    use super::*;
    #[test]
    fn complete_authority_partition() {
        for phase in [
            Phase::PREPARE,
            Phase::CUSTODY_COMMIT,
            Phase::LATCH,
            Phase::ADVANCE_GENERATION,
            Phase::ADVANCE_ACTIVATION,
            Phase::ADVANCE_BOOT,
            Phase::RESERVE,
            Phase::RECORD_COMMIT,
            Phase::DRAIN,
        ] {
            let wall = matches!(phase, Phase::RESERVE | Phase::RECORD_COMMIT | Phase::DRAIN);
            assert_eq!(authorized(Authority::W, phase), wall);
            assert_eq!(authorized(Authority::S, phase), !wall);
        }
        for (transaction, expected) in [
            (serde_json::Value::Null, Phase::RECORD_COMMIT),
            (serde_json::json!("a".repeat(32)), Phase::CUSTODY_COMMIT),
        ] {
            assert_eq!(
                Phase::of_message(
                    &serde_json::json!({"op":"COMMIT","expected":{"transaction_id":transaction}})
                ),
                Some(expected)
            );
        }
    }
}

use super::{activation_anchor as anchor, drain_store, records, writer_protocol};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::ffi::OsStrExt,
};

/// Holds the trusted public-evidence root or the independent runtime directory.
pub struct Directory {
    file: File,
    owner: u32,
}
impl Directory {
    pub fn production(path: &Path, private: bool) -> Result<Self> {
        if !path.is_absolute() {
            return Err(Refusal::ROOT);
        }
        let mut directory =
            Self::open_raw(libc::AT_FDCWD, Path::new("/"), custody::ROOT_UID, false)?;
        let parts: Vec<_> = path.components().skip(1).collect();
        for (index, part) in parts.iter().enumerate() {
            if !matches!(part, std::path::Component::Normal(_)) {
                return Err(Refusal::ROOT);
            }
            directory = Self::open_raw(
                directory.file.as_raw_fd(),
                Path::new(part.as_os_str()),
                custody::ROOT_UID,
                private && index + 1 == parts.len(),
            )?;
        }
        Ok(directory)
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(path: &Path, owner: u32, private: bool) -> Result<Self> {
        Self::open_raw(libc::AT_FDCWD, path, owner, private)
    }
    fn open_raw(parent: RawFd, path: &Path, owner: u32, private: bool) -> Result<Self> {
        let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| Refusal::ROOT)?;
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Refusal::ROOT);
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata().map_err(|_| Refusal::ROOT)?;
        // Every evidence ancestor is owner-controlled; the runtime root is additionally private.
        if !m.is_dir()
            || m.uid() != owner
            || m.mode() & 0o022 != 0
            || (private && m.mode() & 0o7777 != custody::DIRECTORY_MODE)
        {
            return Err(Refusal::ROOT);
        }
        Ok(Self { file, owner })
    }
    fn child(&self, name: &str) -> Result<Self> {
        Self::open_raw(self.file.as_raw_fd(), Path::new(name), self.owner, false)
    }
}
/// A single descriptor entry is replaced on every anchor change; rejected files never populate it.
pub struct DescriptorReader {
    root: Directory,
    cache: Option<(String, anchor::Descriptor)>,
}
impl DescriptorReader {
    pub fn new(root: Directory) -> Self {
        Self { root, cache: None }
    }
    pub fn invalidate(&mut self) {
        self.cache = None;
    }
    fn descriptor(&mut self, old: &Value) -> Result<&anchor::Descriptor> {
        let key = anchor::anchor_digest(old).ok_or(Refusal::DESCRIPTOR)?;
        if self
            .cache
            .as_ref()
            .is_some_and(|(digest, _)| *digest == key)
        {
            return self
                .cache
                .as_ref()
                .map(|(_, d)| d)
                .ok_or(Refusal::DESCRIPTOR);
        }
        self.cache = None;
        let fortress = old["fortress_id"]
            .as_str()
            .filter(|id| protocol::id(id))
            .ok_or(Refusal::DESCRIPTOR)?;
        let directory = self
            .root
            .child(fortress)?
            .child(drain_store::DRAIN_SLOTS[0].0)?
            .child("public")?;
        let name = CString::new("epochs.json").map_err(|_| Refusal::DESCRIPTOR)?;
        let fd = unsafe {
            libc::openat(
                directory.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Refusal::DESCRIPTOR);
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let before = file.metadata().map_err(|_| Refusal::DESCRIPTOR)?;
        if !before.is_file()
            || before.uid() != directory.owner
            || before.nlink() != 1
            || before.mode() & 0o7777 != drain_store::DESCRIPTOR_MODE
            || before.len() > anchor::D_DESCRIPTOR_MAX_BYTES as u64
        {
            return Err(Refusal::DESCRIPTOR);
        }
        let mut bytes = Vec::new();
        (&file)
            .take(anchor::D_DESCRIPTOR_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Refusal::DESCRIPTOR)?;
        let after = file.metadata().map_err(|_| Refusal::DESCRIPTOR)?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
        {
            return Err(Refusal::DESCRIPTOR);
        }
        let pin = old["descriptor_digest"]
            .as_str()
            .ok_or(Refusal::DESCRIPTOR)?;
        let descriptor = anchor::parse_descriptor(&bytes, pin).map_err(|_| Refusal::DESCRIPTOR)?;
        // Raw bytes have no cache lifetime; one parsed descriptor is the only retained public evidence.
        drop(bytes);
        self.cache = Some((key, descriptor));
        self.cache
            .as_ref()
            .map(|(_, d)| d)
            .ok_or(Refusal::DESCRIPTOR)
    }
}
pub fn packet_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
/// Returns the verified ledger commitment, never a signed or durable result.
pub fn verify_commit(
    reader: &mut DescriptorReader,
    role: &str,
    old: &Value,
    message: &Value,
    envelope: &[u8],
) -> Result<String> {
    let e = writer_protocol::decode_envelope(envelope).map_err(|_| Refusal::ENVELOPE)?;
    let body = &e["body"];
    let bytes = crate::smb::jcs::encode(body).map_err(|_| Refusal::ENVELOPE)?;
    if message["body_digest"] != packet_digest(bytes.as_bytes()) {
        return Err(Refusal::BODY_DIGEST);
    }
    if role != drain_store::DRAIN_SLOTS[0].1 || body["role"] != role {
        return Err(Refusal::ROLE);
    }
    // Only the anchor supplies the reserved index and preceding commitment; candidate fields cannot supply their own expectations.
    if body["sequence"] != old["reserved_sequence"]
        || body["prior_commitment"] != old["committed_digest"]
    {
        return Err(Refusal::CHAIN);
    }
    let descriptor = reader.descriptor(old).map_err(|_| Refusal::DESCRIPTOR)?;
    if old["fortress_id"] != descriptor.fortress_id
        || old["machine_id"] != descriptor.machine_id
        || body["identity_id"] != descriptor.identity_id
        || body["machine_id"] != descriptor.machine_id
    {
        return Err(Refusal::DESCRIPTOR);
    }
    let epoch = body["epoch"].as_u64().ok_or(Refusal::KID)?;
    let entry = descriptor
        .epochs
        .iter()
        .find(|e| e.role == role && e.epoch == epoch)
        .ok_or(Refusal::KID)?;
    if body["kid"] != entry.kid {
        return Err(Refusal::KID);
    }
    if body["activation_id"] != old["activation_id"]
        || body["boot_id"] != old["boot_id"]
        || body["generation"] != old["generation_high_water"]
    {
        return Err(Refusal::GRANT);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(e["outer"]["signature"].as_str().ok_or(Refusal::SIGNATURE)?)
        .map_err(|_| Refusal::SIGNATURE)?;
    let scheme = body["signature_scheme"]
        .as_str()
        .ok_or(Refusal::SIGNATURE)?;
    let kind = body["record_kind"].as_str().ok_or(Refusal::SIGNATURE)?;
    // The drain verifies signature, record identity, anchor grant identity, sequence, chain and reserved body digest against its public descriptor and anchor. It holds no key and never re-signs. It does not independently verify lease_id, grant expiry, policy_digest, runtime_digest, config_digest or flow-context joins; those remain the wall's pre-append checks. Independent grant and policy join verification is outside this slice.
    if !super::verify_role(
        role,
        epoch,
        &entry.kid,
        scheme,
        kind,
        bytes.as_bytes(),
        &signature,
        &entry.public_key,
    ) {
        return Err(Refusal::SIGNATURE);
    }
    let commitment = records::join_commitment(&e).ok_or(Refusal::COMMITMENT)?;
    if message["next"]["committed_digest"] != commitment {
        return Err(Refusal::COMMITMENT);
    }
    Ok(commitment)
}
pub fn verify_original(
    role: &str,
    sequence: u64,
    record: &drain_store::DrainRecord,
    envelope: &[u8],
) -> Result<String> {
    let drained = record.anchor["drained_sequence"]
        .as_u64()
        .ok_or(Refusal::CHAIN)?;
    let committed = record.anchor["committed_sequence"]
        .as_u64()
        .ok_or(Refusal::CHAIN)?;
    if drained.checked_add(1) != Some(sequence) || sequence > committed {
        return Err(Refusal::CHAIN);
    }
    let e = writer_protocol::decode_envelope(envelope).map_err(|_| Refusal::ENVELOPE)?;
    if role != drain_store::DRAIN_SLOTS[0].1 || e["body"]["role"] != role {
        return Err(Refusal::ROLE);
    }
    if e["body"]["sequence"] != sequence {
        return Err(Refusal::CHAIN);
    }
    let commitment = records::join_commitment(&e).ok_or(Refusal::COMMITMENT)?;
    // A drained original is the exact signed record this drain verified at commit; equality with the commit ledger is the whole check, and no signature is made.
    if record.ledger.first() != Some(&commitment) {
        return Err(Refusal::COMMITMENT);
    }
    Ok(commitment)
}

#[cfg(test)]
mod verification_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };
    static SERIAL: AtomicUsize = AtomicUsize::new(0);
    struct Fixture {
        path: PathBuf,
        reader: DescriptorReader,
        old: Value,
        message: Value,
        envelope: Vec<u8>,
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "dv-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            let corpus: Value =
                serde_json::from_str(include_str!("record_join_vectors.json")).unwrap();
            let mut body = corpus["cases"][0]["records"][0]["body"].clone();
            let closure: Value =
                serde_json::from_str(include_str!("closure_vectors.json")).unwrap();
            let mut old = closure["anchor"].clone();
            // This public synthetic seed is fixture material only, never reachable from production.
            let key = SigningKey::from_bytes(&[7; 32]);
            let role = drain_store::DRAIN_SLOTS[0].1;
            body["kid"] = json!(super::super::role_kid(
                role,
                body["epoch"].as_u64().unwrap(),
                &key.verifying_key().to_bytes()
            )
            .unwrap());
            old["machine_id"] = body["machine_id"].clone();
            old["activation_id"] = body["activation_id"].clone();
            old["boot_id"] = body["boot_id"].clone();
            old["generation_high_water"] = body["generation"].clone();
            old["reserved_sequence"] = body["sequence"].clone();
            let canonical = crate::smb::jcs::encode(&body).unwrap();
            old["reserved_body_digest"] = json!(packet_digest(canonical.as_bytes()));
            let domain = super::super::signer_contract::ROLE_REGISTRY
                .iter()
                .find(|r| r.0 == role)
                .unwrap()
                .1;
            let signature = key
                .sign(&[domain.as_bytes(), canonical.as_bytes()].concat())
                .to_bytes();
            let envelope = writer_protocol::envelope(canonical.as_bytes(), &signature).unwrap();
            let descriptor = json!({"version":1,"fortress_id":old["fortress_id"],"machine_id":body["machine_id"],"identity_id":body["identity_id"],"epochs":[{"role":role,"epoch":body["epoch"],"kid":body["kid"],"public_key":hex::encode(key.verifying_key().to_bytes())}]});
            let bytes = crate::smb::jcs::encode(&descriptor).unwrap();
            old["descriptor_digest"] = json!(packet_digest(bytes.as_bytes()));
            let fort = path.join(old["fortress_id"].as_str().unwrap());
            let slot = fort.join(drain_store::DRAIN_SLOTS[0].0);
            let public = slot.join("public");
            for d in [&fort, &slot, &public] {
                fs::create_dir(d).unwrap();
                fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
            }
            fs::write(public.join("epochs.json"), bytes).unwrap();
            fs::set_permissions(
                public.join("epochs.json"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            let mut next = old.clone();
            next["reserved_body_digest"] = Value::Null;
            next["committed_sequence"] = body["sequence"].clone();
            next["committed_digest"] = json!(records::join_commitment(
                &writer_protocol::decode_envelope(&envelope).unwrap()
            )
            .unwrap());
            let message = json!({"version":1,"op":"COMMIT","request_id":"c".repeat(32),"expected":old,"next":next,"body_digest":packet_digest(canonical.as_bytes())});
            let reader = DescriptorReader::new(
                Directory::open_raw(libc::AT_FDCWD, &path, unsafe { libc::geteuid() }, true)
                    .unwrap(),
            );
            Self {
                path,
                reader,
                old,
                message,
                envelope,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let f = self.path.join(self.old["fortress_id"].as_str().unwrap());
            let s = f.join(drain_store::DRAIN_SLOTS[0].0);
            let p = s.join("public");
            let _ = fs::remove_file(p.join("epochs.json"));
            for d in [p, s, f, self.path.clone()] {
                let _ = fs::remove_dir(d);
            }
        }
    }
    #[test]
    fn commit_verification_uses_pinned_evidence() {
        let mut f = Fixture::new();
        let role = drain_store::DRAIN_SLOTS[0].1;
        assert!(anchor::valid(&f.old));
        assert_eq!(
            verify_commit(&mut f.reader, role, &f.old, &f.message, &f.envelope).unwrap(),
            f.message["next"]["committed_digest"]
        );
        for (field, stage) in [
            ("body_digest", Refusal::BODY_DIGEST),
            ("committed_digest", Refusal::COMMITMENT),
        ] {
            let mut m = f.message.clone();
            if field == "body_digest" {
                m[field] = json!(format!("sha256:{}", "e".repeat(64)));
            } else {
                m["next"][field] = json!(format!("sha256:{}", "e".repeat(64)));
            }
            assert_eq!(
                verify_commit(&mut f.reader, role, &f.old, &m, &f.envelope).unwrap_err(),
                stage
            );
        }
        let mut old = f.old.clone();
        old["committed_digest"] = json!(format!("sha256:{}", "e".repeat(64)));
        assert_eq!(
            verify_commit(&mut f.reader, role, &old, &f.message, &f.envelope).unwrap_err(),
            Refusal::CHAIN
        );
        assert_eq!(
            verify_commit(&mut f.reader, "unknown", &f.old, &f.message, &f.envelope).unwrap_err(),
            Refusal::ROLE
        );
        assert_eq!(
            verify_commit(&mut f.reader, role, &f.old, &f.message, b" {}").unwrap_err(),
            Refusal::ENVELOPE
        );
    }
    #[test]
    fn original_is_bound_to_committed_ledger() {
        let f = Fixture::new();
        let role = drain_store::DRAIN_SLOTS[0].1;
        let digest = f.message["next"]["committed_digest"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut record = drain_store::DrainRecord {
            anchor: f.message["next"].clone(),
            last: drain_store::LastOp {
                authority: Authority::W,
                phase: drain_store::Phase::RECORD_COMMIT,
                request_id: "c".repeat(32),
                request_sha256: packet_digest(&f.envelope),
            },
            ledger: vec![digest.clone()],
        };
        assert_eq!(
            verify_original(role, 1, &record, &f.envelope).unwrap(),
            digest
        );
        record.ledger[0] = format!("sha256:{}", "e".repeat(64));
        assert_eq!(
            verify_original(role, 1, &record, &f.envelope).unwrap_err(),
            Refusal::COMMITMENT
        );
        assert_eq!(
            verify_original(role, 2, &record, &f.envelope).unwrap_err(),
            Refusal::CHAIN
        );
    }
}
