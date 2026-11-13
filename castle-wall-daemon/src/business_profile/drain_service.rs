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
    #[cfg(feature = "test-isolation")]
    signer_group: Option<String>,
}
impl Classifier {
    pub fn production() -> Self {
        Self {
            #[cfg(feature = "test-isolation")]
            signer_pid: None,
            #[cfg(feature = "test-isolation")]
            signer_group: None,
        }
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(signer_pid: i32, signer_group: String) -> Self {
        Self {
            signer_pid: Some(signer_pid),
            signer_group: Some(signer_group),
        }
    }
    fn partition_group<'a>(&'a self, configured: &'a str) -> &'a str {
        #[cfg(feature = "test-isolation")]
        if let Some(group) = &self.signer_group {
            return group;
        }
        configured
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
    W(Box<WallMainBinding>),
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
            let wall = WallMainBinding::capture(
                fd,
                &config.wall_policy(),
                bus,
                peer_uid,
                owner,
                end.clone(),
            )
            .map_err(|_| Refusal::CLASSIFY)?;
            // Snapshot evidence cannot confer wall authority inside the signer partition, even if the process moved during capture.
            if wall.cgroup() == classifier.partition_group(&configured) {
                return Err(Refusal::CLASSIFY);
            }
            Self::W(Box::new(wall))
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

use drain_store::{
    DrainRecord, EventSink, HeldRoot, LastOp, Phase, PublishOutcome, StateLock, Store, StoreFaults,
};
use protocol::{Direction, Operation};
use std::{io, os::fd::OwnedFd, sync::Arc};
const SLOT: &str = drain_store::DRAIN_SLOTS[0].0;
const WIRE_ROLE: &str = drain_store::DRAIN_SLOTS[0].1;
const SOCKET_NAME: &str = "drain.sock"; // Must match DRAIN_SOCKET in drain_protocol.rs.
const POLL_MS: i32 = super::signer_watchdog::WATCHDOG_TICK_MS;
#[derive(Debug, Clone, Copy)]
pub enum StartState {
    LoadConfig,
    Lock,
    ValidateState,
    PrepareSocket,
    Listen,
    Ready,
}
#[derive(Debug, Clone, Copy)]
pub enum RequestState {
    Bind,
    Decode,
    Role,
    Reconcile,
    Authority,
    Retry,
    Propose,
    Verify,
    Capacity,
    Store,
    Revalidate,
    Reply,
}
/// The required sink has an explicit production no-op; test logs never contain candidate record bytes.
pub struct Diagnostics {
    events: EventSink,
    #[cfg(feature = "test-isolation")]
    seam: Option<PathBuf>,
}
impl Diagnostics {
    pub fn production() -> Self {
        Self {
            events: EventSink::none(),
            #[cfg(feature = "test-isolation")]
            seam: None,
        }
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(root: &Path) -> Result<Self> {
        Ok(Self {
            events: EventSink::from_seam_root(root).map_err(|_| Refusal::ROOT)?,
            seam: Some(root.to_owned()),
        })
    }
    fn event(&self, name: &str, id: Option<&str>, settlement: Option<&str>) -> Result<()> {
        self.events
            .emit(name, id, None, None, settlement)
            .map_err(|_| Refusal::STORE)
    }
    fn refuse(&self, stage: Refusal, id: Option<&str>) -> Result<()> {
        #[cfg(feature = "test-isolation")]
        if let Some(root) = &self.seam {
            let mut f = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(custody::PRIVATE_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(root.join("refusals.jsonl"))
                .map_err(|_| Refusal::STORE)?;
            let v = serde_json::json!({"stage":format!("{stage:?}"),"slot":SLOT,"request_id":id});
            writeln!(
                f,
                "{}",
                crate::smb::jcs::encode(&v).map_err(|_| Refusal::STORE)?
            )
            .map_err(|_| Refusal::STORE)?;
        }
        let _ = (stage, id);
        Ok(())
    }
}
pub struct Dependencies {
    pub config: HeldConfig,
    pub state: HeldRoot,
    pub runtime: Directory,
    pub descriptor: DescriptorReader,
    pub bus: BusTarget,
    pub peer_uid: u32,
    pub owner: u32,
    pub classifier: Classifier,
    pub faults: StoreFaults,
    pub store_events: EventSink,
    pub diagnostics: Diagnostics,
    pub notifier: Box<dyn super::writer_service::Notifier>,
    pub clock: writer_peer::Clock,
}
struct SocketGuard<'a> {
    runtime: &'a Directory,
    listener: OwnedFd,
    dev: u64,
    ino: u64,
}
fn socket_stat(runtime: &Directory) -> Result<Option<libc::stat>> {
    let name = CString::new(SOCKET_NAME).map_err(|_| Refusal::SOCKET)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            runtime.file.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(Refusal::SOCKET);
    }
    Ok(Some(st))
}
fn unlink_socket(runtime: &Directory) -> Result<()> {
    let name = CString::new(SOCKET_NAME).map_err(|_| Refusal::SOCKET)?;
    if unsafe { libc::unlinkat(runtime.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        Err(Refusal::SOCKET)
    } else {
        Ok(())
    }
}
fn prepare_socket<'a>(runtime: &'a Directory, _lock: &StateLock) -> Result<SocketGuard<'a>> {
    // Only the singleton state-lock holder may remove the fixed stale socket; no arbitrary runtime entry is cleaned.
    if let Some(st) = socket_stat(runtime)? {
        if st.st_mode & libc::S_IFMT != libc::S_IFSOCK || st.st_uid != runtime.owner {
            return Err(Refusal::SOCKET);
        }
        unlink_socket(runtime)?;
    }
    signer_peer::drop_capabilities_with(signer_peer::CapabilityDrop::Signer)
        .map_err(|_| Refusal::ROOT)?;
    let path = PathBuf::from(format!(
        "/proc/self/fd/{}/{SOCKET_NAME}",
        runtime.file.as_raw_fd()
    ));
    let listener = signer_peer::listen(&path).map_err(|_| Refusal::SOCKET)?;
    let st = socket_stat(runtime)?.ok_or(Refusal::SOCKET)?;
    Ok(SocketGuard {
        runtime,
        listener,
        dev: st.st_dev,
        ino: st.st_ino,
    })
}
impl Drop for SocketGuard<'_> {
    fn drop(&mut self) {
        if let Ok(Some(st)) = socket_stat(self.runtime) {
            if st.st_dev == self.dev && st.st_ino == self.ino {
                let _ = unlink_socket(self.runtime);
            }
        }
    }
}
fn deadline(clock: &writer_peer::Clock, ms: usize) -> Result<Deadline> {
    let now = clock().map_err(|_| Refusal::DEADLINE)?;
    let end = now
        .checked_add(
            (ms as u64)
                .checked_mul(writer_peer::NS_PER_MS)
                .ok_or(Refusal::DEADLINE)?,
        )
        .ok_or(Refusal::DEADLINE)?;
    Deadline::new(clock.clone(), end).map_err(|_| Refusal::DEADLINE)
}
fn send_before(fd: RawFd, bytes: &[u8], end: &Deadline) -> Result<()> {
    loop {
        end.check().map_err(|_| Refusal::DEADLINE)?;
        match signer_peer::send(fd, bytes, &[]) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(Refusal::REPLY),
        }
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        if unsafe { libc::poll(&mut p, 1, POLL_MS) } < 0 {
            return Err(Refusal::REPLY);
        }
    }
}
fn response(
    op: &str,
    id: &str,
    anchor: Option<&Value>,
    sequence: Option<u64>,
    uncertain: bool,
) -> Result<Vec<u8>> {
    let mut h = protocol::header(op, id, WIRE_ROLE);
    let mut payload = Vec::new();
    if matches!(op, "ANCHOR_ACK" | "READ_REPLY") {
        if let Some(a) = anchor {
            payload = crate::smb::jcs::encode(a)
                .map_err(|_| Refusal::REPLY)?
                .into_bytes();
        }
        h["payload_length"] = serde_json::json!(payload.len());
        h["anchor_digest"] = serde_json::json!(anchor.and_then(anchor::anchor_digest));
        if op == "READ_REPLY" {
            h["state"] = serde_json::json!(if anchor.is_some() {
                "PRESENT"
            } else {
                "ABSENT"
            });
            h["latched"] =
                serde_json::json!(anchor.is_some_and(|a| a["recovery_required"] == true));
            h["uncertain"] = serde_json::json!(uncertain);
        }
    } else if op == "ORIGINAL_ACK" {
        h["sequence"] = serde_json::json!(sequence.ok_or(Refusal::REPLY)?);
        h["drained_digest"] = anchor.ok_or(Refusal::REPLY)?["drained_digest"].clone();
    }
    protocol::encode(&h, &payload, Direction::FromDrain).map_err(|_| Refusal::REPLY)
}
struct PreparedReply {
    bytes: Vec<u8>,
    published: bool,
}
struct Executor<'a, 'b> {
    store: Store<'a>,
    reader: &'b mut DescriptorReader,
    diagnostics: &'b Diagnostics,
    fortress: &'b str,
    closed: [bool; 2],
    copy_cap_refusals: usize,
}
fn authority_index(a: Authority) -> usize {
    match a {
        Authority::W => 0,
        Authority::S => 1,
    }
}
impl Executor<'_, '_> {
    fn close_authority(&mut self, a: Authority, id: &str) -> Result<()> {
        let index = authority_index(a);
        if !self.closed[index] {
            self.closed[index] = true;
            self.diagnostics.refuse(Refusal::RETRY, Some(id))?;
        }
        Ok(())
    }
    fn publish(&mut self, outcome: PublishOutcome) -> Result<()> {
        match outcome {
            PublishOutcome::Durable => Ok(()),
            PublishOutcome::PrePublication(drain_store::StoreRefusal::CAP) => {
                // A saturated fixed counter reports copy backpressure without retaining per-request history.
                self.copy_cap_refusals = self.copy_cap_refusals.saturating_add(1);
                Err(Refusal::STORE)
            }
            PublishOutcome::PrePublication(_) | PublishOutcome::Uncertain(_) => Err(Refusal::STORE),
        }
    }
    fn process(
        &mut self,
        authority: Authority,
        frame: &protocol::Frame<'_>,
        packet: &[u8],
    ) -> Result<PreparedReply> {
        let _state = RequestState::Role;
        if frame.role != WIRE_ROLE {
            return Err(Refusal::ROLE);
        }
        if self.closed[authority_index(authority)] {
            return Err(Refusal::AUTHORITY);
        }
        if matches!(frame.operation, Operation::Read) {
            let observation = self.store.observe(SLOT);
            return Ok(PreparedReply {
                bytes: response(
                    "READ_REPLY",
                    &frame.request_id,
                    observation.anchor.as_ref(),
                    None,
                    observation.uncertain,
                )?,
                published: false,
            });
        }
        let _state = RequestState::Reconcile;
        // Unknown slots observe as uncertain absence; only the fixed producer slot can ever reach this mutation gate.
        self.store.reconcile(SLOT).map_err(|_| Refusal::RECONCILE)?;
        if self.store.observe(SLOT).uncertain {
            return Err(Refusal::RECONCILE);
        }
        let phase = match &frame.operation {
            Operation::Anchor { message, .. } => {
                Phase::of_message(message).ok_or(Refusal::AUTHORITY)?
            }
            Operation::Original { .. } => Phase::DRAIN,
            _ => return Err(Refusal::AUTHORITY),
        };
        let _state = RequestState::Authority;
        if !authorized(authority, phase) {
            return Err(Refusal::AUTHORITY);
        }
        let old = self.store.record(SLOT).cloned();
        let digest = packet_digest(packet);
        // Request identity uses the phase's authority only after the captured peer passed the equality check above.
        let last = LastOp {
            authority: Authority::for_phase(phase),
            phase,
            request_id: frame.request_id.clone(),
            request_sha256: digest,
        };
        match &frame.operation {
            Operation::Anchor { message, envelope } => {
                let _state = RequestState::Retry;
                if let Some(record) = &old {
                    if record.last.authority == authority
                        && record.last.phase == phase
                        && record.last.request_id == frame.request_id
                    {
                        if record.last.request_sha256 != last.request_sha256 {
                            self.close_authority(authority, &frame.request_id)?;
                            return Err(Refusal::RETRY);
                        }
                        return Ok(PreparedReply {
                            bytes: response(
                                "ANCHOR_ACK",
                                &frame.request_id,
                                Some(&record.anchor),
                                None,
                                false,
                            )?,
                            published: false,
                        });
                    }
                }
                let _state = RequestState::Propose;
                let prior = old
                    .as_ref()
                    .map_or(anchor::Prior::Absent, |r| anchor::Prior::Present(&r.anchor));
                let next = anchor::propose(prior, message).ok_or(Refusal::PROPOSE)?;
                if next["fortress_id"] != self.fortress || next["role"] != WIRE_ROLE {
                    return Err(Refusal::ROLE);
                }
                let mut ledger = old.as_ref().map_or_else(Vec::new, |r| r.ledger.clone());
                if phase == Phase::RECORD_COMMIT {
                    let _state = RequestState::Verify;
                    let commitment = verify_commit(
                        self.reader,
                        &frame.role,
                        &old.as_ref().ok_or(Refusal::PROPOSE)?.anchor,
                        message,
                        envelope,
                    )?;
                    let _state = RequestState::Capacity;
                    // A missing head original, copy cap or latch can stop DRAIN and then COMMIT; refusal never evicts and no finalization headroom is promised.
                    if ledger.len() >= drain_store::D_UNDRAINED_MAX {
                        return Err(Refusal::CAPACITY);
                    }
                    ledger.push(commitment);
                }
                let record = DrainRecord {
                    anchor: next,
                    last,
                    ledger,
                };
                let _state = RequestState::Store;
                let outcome = self.store.publish_record(SLOT, &record);
                self.publish(outcome)?;
                self.reader.invalidate();
                // Custody and record COMMIT ACKs require the store's fsync plus exact readback, followed by peer revalidation.
                Ok(PreparedReply {
                    bytes: response(
                        "ANCHOR_ACK",
                        &frame.request_id,
                        Some(&record.anchor),
                        None,
                        false,
                    )?,
                    published: true,
                })
            }
            Operation::Original { sequence, envelope } => {
                let mut record = old.ok_or(Refusal::PROPOSE)?;
                let drained = record.anchor["drained_sequence"]
                    .as_u64()
                    .ok_or(Refusal::PROPOSE)?;
                if *sequence == drained || drained.checked_add(1) == Some(*sequence) {
                    if let Some(copy) = self.store.copy(SLOT, *sequence) {
                        if copy != *envelope {
                            self.close_authority(authority, &frame.request_id)?;
                            return Err(Refusal::RETRY);
                        }
                    }
                }
                if *sequence == drained {
                    if self.store.copy(SLOT, *sequence).is_none() {
                        return Err(Refusal::PROPOSE);
                    }
                    let outcome = self.store.publish_original(SLOT, *sequence, envelope);
                    self.publish(outcome)?;
                    return Ok(PreparedReply {
                        bytes: response(
                            "ORIGINAL_ACK",
                            &frame.request_id,
                            Some(&record.anchor),
                            Some(*sequence),
                            false,
                        )?,
                        published: true,
                    });
                }
                let commitment = verify_original(&frame.role, *sequence, &record, envelope)?;
                let mut next = record.anchor.clone();
                next["drained_sequence"] = serde_json::json!(sequence);
                next["drained_digest"] = serde_json::json!(commitment);
                let proposal = serde_json::json!({"version":1,"op":"DRAIN","request_id":frame.request_id,"expected":record.anchor,"next":next});
                let outcome = self.store.publish_original(SLOT, *sequence, envelope);
                self.publish(outcome)?;
                // Only a durable original permits the reducer to advance the drain watermark.
                let next = anchor::propose(anchor::Prior::Present(&record.anchor), &proposal)
                    .ok_or(Refusal::PROPOSE)?;
                record.anchor = next;
                record.last = last;
                record.ledger.remove(0);
                let outcome = self.store.publish_record(SLOT, &record);
                self.publish(outcome)?;
                self.reader.invalidate();
                // Only this acknowledgment authorizes the wall to release log space; REFUSED, a disconnect, a durable copy alone or an uncertain outcome never does.
                Ok(PreparedReply {
                    bytes: response(
                        "ORIGINAL_ACK",
                        &frame.request_id,
                        Some(&record.anchor),
                        Some(*sequence),
                        false,
                    )?,
                    published: true,
                })
            }
            _ => Err(Refusal::AUTHORITY),
        }
    }
    fn request(
        &mut self,
        fd: RawFd,
        binding: &Binding,
        bus: &BusTarget,
        end: Deadline,
    ) -> Result<()> {
        let _state = RequestState::Bind;
        let packet =
            signer_peer::receive(fd, protocol::D_REQUEST_MAX_BYTES).map_err(|_| Refusal::BIND)?;
        binding.packet(&packet)?;
        let _state = RequestState::Decode;
        let frame =
            protocol::decode(&packet.bytes, Direction::ToDrain).map_err(|_| Refusal::ENVELOPE)?;
        self.diagnostics
            .event("RequestAdmitted", Some(&frame.request_id), None)?;
        let prepared = self.process(binding.authority(), &frame, &packet.bytes);
        let mut published = false;
        let result = match prepared {
            Ok(reply) => {
                published = reply.published;
                let _state = RequestState::Revalidate;
                binding.revalidate(bus, end.clone()).and_then(|()| {
                    let _state = RequestState::Reply;
                    send_before(fd, &reply.bytes, &end)?;
                    self.diagnostics
                        .event("ReplySent", Some(&frame.request_id), None)
                })
            }
            Err(stage) => {
                self.diagnostics.refuse(stage, Some(&frame.request_id))?;
                if stage != Refusal::STORE && stage != Refusal::RETRY {
                    let bytes = response("REFUSED", &frame.request_id, None, None, false)?;
                    let _ = send_before(fd, &bytes, &end);
                }
                Err(stage)
            }
        };
        // A failed completion after Durable keeps the attempted image for independent reconciliation; a no-store retry cannot invent clearing evidence.
        if result.is_err() && published {
            self.store.mark_uncertain(SLOT);
        }
        let settlement = if self.store.observe(SLOT).uncertain {
            "uncertain"
        } else if published {
            "durable"
        } else {
            "pre_publication"
        };
        self.diagnostics
            .event("RequestSettled", Some(&frame.request_id), Some(settlement))?;
        result
    }
}
pub fn run(mut deps: Dependencies) -> Result<()> {
    let setup = (|| {
        let _state = StartState::Lock;
        let lock = StateLock::acquire(&deps.state).map_err(|_| Refusal::ROOT)?;
        Ok(lock)
    })();
    let lock = match setup {
        Ok(lock) => lock,
        Err(e) => {
            let _ = deps.notifier.notify("STATUS=drain refused at start");
            return Err(e);
        }
    };
    let _state = StartState::ValidateState;
    let store = match Store::open(
        &deps.state,
        &deps.config.value.fortress_id,
        &lock,
        deps.owner,
        deps.faults,
        deps.store_events,
    ) {
        Ok(store) => store,
        Err(_) => {
            let _ = deps.notifier.notify("STATUS=drain refused at start");
            return Err(Refusal::STORE);
        }
    };
    let _state = StartState::PrepareSocket;
    let socket = match prepare_socket(&deps.runtime, &lock) {
        Ok(s) => s,
        Err(e) => {
            let _ = deps.notifier.notify("STATUS=drain refused at start");
            return Err(e);
        }
    };
    let observation = store.observe(SLOT);
    let _state = StartState::Ready;
    deps.notifier
        .notify(&format!(
            "READY=1\nSTATUS=drain ready; {} roles; latched={}; uncertain={}",
            drain_store::DRAIN_SLOTS.len(),
            observation.latched,
            observation.uncertain
        ))
        .map_err(|_| Refusal::REPLY)?;
    let mut executor = Executor {
        store,
        reader: &mut deps.descriptor,
        diagnostics: &deps.diagnostics,
        fortress: &deps.config.value.fortress_id,
        closed: [false; 2],
        copy_cap_refusals: 0,
    };
    let mut reported_caps = 0;
    let mut peers: Vec<(OwnedFd, Binding)> = Vec::new();
    // A stalled store step stalls every peer, including the signer's recovery read; no request is admitted while one is unsettled.
    loop {
        let mut polls: Vec<_> = std::iter::once(libc::pollfd {
            fd: socket.listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .chain(peers.iter().map(|(fd, _)| libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }))
        .collect();
        let result =
            unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, POLL_MS) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Refusal::BIND);
        }
        for index in (0..peers.len()).rev() {
            let events = polls[index + 1].revents;
            if events == 0 {
                continue;
            }
            let (fd, binding) = &peers[index];
            if events & libc::POLLIN == 0 || executor.closed[authority_index(binding.authority())] {
                peers.remove(index);
                continue;
            }
            let end = deadline(&deps.clock, protocol::D_REQUEST_DEADLINE_MS)?;
            if let Err(stage) = executor.request(fd.as_raw_fd(), binding, &deps.bus, end) {
                deps.diagnostics.refuse(stage, None)?;
                peers.remove(index);
            }
            if reported_caps != executor.copy_cap_refusals {
                let observation = executor.store.observe(SLOT);
                deps.notifier
                    .notify(&format!(
                    "STATUS=drain ready; {} roles; latched={}; uncertain={}; copy_cap_refusals={}",
                    drain_store::DRAIN_SLOTS.len(), observation.latched, observation.uncertain,
                    executor.copy_cap_refusals,
                ))
                    .map_err(|_| Refusal::REPLY)?;
                reported_caps = executor.copy_cap_refusals;
            }
        }
        if polls[0].revents & libc::POLLIN != 0 {
            let fd =
                signer_peer::accept(socket.listener.as_raw_fd()).map_err(|_| Refusal::CLASSIFY)?;
            let end = deadline(&deps.clock, protocol::D_CLASSIFY_DEADLINE_MS)?;
            // The two admitted authority slots plus this synchronous classifier are the complete connection bound.
            if peers.len() + 1 > protocol::D_CONNECTIONS_MAX {
                continue;
            }
            match Binding::capture(
                fd.as_raw_fd(),
                &deps.config.value,
                &deps.bus,
                deps.peer_uid,
                deps.owner,
                &deps.classifier,
                end,
            ) {
                Ok(binding) => {
                    if executor.closed[authority_index(binding.authority())]
                        || peers
                            .iter()
                            .any(|(_, b)| b.authority() == binding.authority())
                    {
                        continue;
                    }
                    signer_peer::passcred(fd.as_raw_fd()).map_err(|_| Refusal::BIND)?;
                    peers.push((fd, binding));
                }
                Err(stage) => deps.diagnostics.refuse(stage, None)?,
            }
        }
    }
}

#[cfg(feature = "test-isolation")]
pub const DRAIN_TEST_SEAM_MARKER: &str = "sanctuary-drain-test-seam-v1";
#[cfg(feature = "test-isolation")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeamConfig {
    owner: u32,
    peer_uid: u32,
    signer_pid: i32,
    signer_group: String,
    bus: BusTarget,
}
#[cfg(feature = "test-isolation")]
pub fn test_entry(root: &Path) -> Result<()> {
    let bytes = custody::read_pinned(
        &root.join("seam.json"),
        unsafe { libc::geteuid() },
        custody::CONFIG_MAX_BYTES,
        custody::PRIVATE_MODE,
    )
    .map_err(|_| Refusal::CONFIG)?;
    let seam: SeamConfig = serde_json::from_value(
        protocol::canonical(&bytes, custody::CONFIG_MAX_BYTES).map_err(|_| Refusal::CONFIG)?,
    )
    .map_err(|_| Refusal::CONFIG)?;
    run(Dependencies {
        config: HeldConfig::isolated(&root.join("config.json"), seam.owner)?,
        state: HeldRoot::isolated_under(&root.join("state"), seam.owner)
            .map_err(|_| Refusal::ROOT)?,
        runtime: Directory::isolated(&root.join("runtime"), seam.owner, true)?,
        descriptor: DescriptorReader::new(Directory::isolated(
            &root.join("custody"),
            seam.owner,
            true,
        )?),
        bus: seam.bus,
        peer_uid: seam.peer_uid,
        owner: seam.owner,
        classifier: Classifier::isolated(seam.signer_pid, seam.signer_group),
        faults: StoreFaults::from_seam_root(root).map_err(|_| Refusal::ROOT)?,
        store_events: EventSink::from_seam_root(root).map_err(|_| Refusal::ROOT)?,
        diagnostics: Diagnostics::isolated(root)?,
        notifier: Box::new(super::writer_service::SystemNotifier),
        clock: Arc::new(super::signer_watchdog::boottime_ns),
    })
}
pub fn production() -> Result<()> {
    run(Dependencies {
        config: HeldConfig::production()?,
        state: HeldRoot::production().map_err(|_| Refusal::ROOT)?,
        runtime: Directory::production(
            Path::new(protocol::DRAIN_SOCKET)
                .parent()
                .ok_or(Refusal::ROOT)?,
            true,
        )?,
        descriptor: DescriptorReader::new(Directory::production(
            Path::new(custody::CUSTODY_ROOT),
            true,
        )?),
        bus: BusTarget::production(),
        peer_uid: custody::ROOT_UID,
        owner: custody::ROOT_UID,
        classifier: Classifier::production(),
        faults: StoreFaults::none(),
        store_events: EventSink::none(),
        diagnostics: Diagnostics::production(),
        notifier: Box::new(super::writer_service::SystemNotifier),
        clock: Arc::new(super::signer_watchdog::boottime_ns),
    })
}

#[cfg(feature = "test-isolation")]
use std::io::Write;
