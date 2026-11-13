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
