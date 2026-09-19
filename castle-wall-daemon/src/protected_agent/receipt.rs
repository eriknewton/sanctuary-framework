//! Canonical, domain-separated receipts. The journal MAC key is never used here.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PINS_PATH: &str = "/etc/sanctuary/launcher/receipt-pins-v1.json";
pub const ADMISSION_KEY_PATH: &str = "/var/lib/sanctuary/launcher/admission-signing.key";
pub const COMPLETION_KEY_PATH: &str = "/var/lib/sanctuary-stop-owner/completion-signing.key";
pub const MAX_RECEIPT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Domain {
    CreateAdmissionV1,
    ReleaseV1,
    StopFailureV1,
    ReleasedUnresolvedV1,
    PreparedExtinctionV1,
    StopCompletionV1,
}

impl Domain {
    pub fn tag(self) -> &'static str {
        match self {
            Self::CreateAdmissionV1 => "sanctuary.protected-agent.create-admission/v1\n",
            Self::ReleaseV1 => "sanctuary.protected-agent.release/v1\n",
            Self::StopFailureV1 => "sanctuary.protected-agent.stop-failure/v1\n",
            Self::ReleasedUnresolvedV1 => "sanctuary.protected-agent.released-unresolved/v1\n",
            Self::PreparedExtinctionV1 => "sanctuary.protected-agent.prepared-extinction/v1\n",
            Self::StopCompletionV1 => "sanctuary.protected-agent.stop-completion/v1\n",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation {
    pub boot_id: String,
    pub daemon_invocation: String,
    pub fortress_id: String,
    pub manifest_generation: String,
    pub ownership_generation: String,
    pub reservation_nonce: String,
    pub reservation_hash: String,
    pub account: String,
    pub uid: u32,
    pub gid: u32,
    pub profile_id: String,
    pub profile_hash: String,
    pub executable_sha256: String,
    pub unit_name: String,
}

impl Generation {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.boot_id.is_empty()
            || self.daemon_invocation.is_empty()
            || self.manifest_generation.is_empty()
            || self.ownership_generation.is_empty()
            || self.account.is_empty()
            || self.profile_id != "agent-v1"
            || self.uid == 0
            || self.gid == 0
            || self.fortress_id.len() < 8
            || self.fortress_id.len() > 64
            || !self
                .fortress_id
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err("invalid generation identity");
        }
        for digest in [
            &self.reservation_nonce,
            &self.reservation_hash,
            &self.profile_hash,
            &self.executable_sha256,
        ] {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err("invalid digest or nonce");
            }
        }
        if self.unit_name != deterministic_unit_name(self) {
            return Err("unit name mismatch");
        }
        Ok(())
    }
}

pub fn deterministic_unit_name(g: &Generation) -> String {
    let mut h = Sha256::new();
    for field in [
        &g.boot_id,
        &g.daemon_invocation,
        &g.fortress_id,
        &g.manifest_generation,
        &g.uid.to_string(),
        &g.ownership_generation,
        &g.reservation_nonce,
    ] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    format!("sanctuary-agent-v1-{}.service", hex::encode(h.finalize()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerIdentity {
    pub unit_name: String,
    pub cgroup_path: String,
    pub cgroup_dev: u64,
    pub cgroup_ino: u64,
    pub main_pid: u32,
    pub main_start_time: u64,
}

impl ManagerIdentity {
    pub fn validate(&self, g: &Generation) -> Result<(), &'static str> {
        if self.unit_name != g.unit_name
            || self.cgroup_dev == 0
            || self.cgroup_ino == 0
            || self.main_pid == 0
            || self.main_start_time == 0
            || self.cgroup_path.starts_with('/')
            || self.cgroup_path.contains("..")
            || !self.cgroup_path.starts_with("system.slice/")
            || !self.cgroup_path.ends_with(&g.unit_name)
        {
            return Err("invalid manager identity");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBody {
    pub generation: Generation,
    pub manager: Option<ManagerIdentity>,
    pub hook: Option<String>,
    pub attempt_id: Option<String>,
    pub attempted_scope: Option<String>,
    /// Candidate (a) union (b) identities are signed diagnostics, never owner
    /// stop authority or cgroup selection.
    pub candidate_uids: Vec<u32>,
    pub old_release_hash: Option<String>,
    pub positive_extinction: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt {
    pub domain: Domain,
    pub key_id: String,
    pub body: ReceiptBody,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    pub schema: u32,
    pub algorithm: String,
    pub admission_public: String,
    pub admission_key_id: String,
    pub completion_public: String,
    pub completion_key_id: String,
}

pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

impl Pins {
    pub fn validate(&self) -> Result<(VerifyingKey, VerifyingKey), &'static str> {
        if self.schema != 1 || self.algorithm != "ed25519" {
            return Err("unsupported pins");
        }
        let a = decode_public(&self.admission_public)?;
        let c = decode_public(&self.completion_public)?;
        if self.admission_key_id != key_id(&a) || self.completion_key_id != key_id(&c) || a == c {
            return Err("pin mismatch");
        }
        Ok((a, c))
    }
}

fn decode_public(hex_text: &str) -> Result<VerifyingKey, &'static str> {
    let bytes: [u8; 32] = hex::decode(hex_text)
        .map_err(|_| "bad public key")?
        .try_into()
        .map_err(|_| "bad public key length")?;
    crate::crypto::parse_strict_verifying_key(&bytes).map_err(|_| "bad authority public key")
}

fn signing_bytes(domain: Domain, body: &ReceiptBody) -> Result<Vec<u8>, &'static str> {
    body.generation.validate()?;
    if let Some(manager) = &body.manager {
        manager.validate(&body.generation)?;
    }
    match domain {
        Domain::StopFailureV1 => {
            if body.manager.is_none() || body.positive_extinction.is_some()
                || !body.attempt_id.as_ref().is_some_and(|id| is_hex_64(id))
                || !body.hook.as_deref().is_some_and(|h| matches!(h,
                    "reclaim drift: the safety net install failed before readiness was refused" |
                    "boot-time owned-table loss: the safety net install failed" |
                    "startup ownership loss: the safety net install failed before the unwind" |
                    "startup ownership reading indeterminate: no install is attempted on absent evidence" |
                    "runtime loss: the safety net install failed and will be retried" |
                    "post-ready ownership reading indeterminate")) {
                return Err("invalid stop-failure action");
            }
        }
        Domain::ReleasedUnresolvedV1 => {
            if body.manager.is_none() || body.hook.is_some() || body.attempt_id.is_some()
                || body.positive_extinction.is_some() || body.old_release_hash.is_some() {
                return Err("invalid released row");
            }
        }
        Domain::PreparedExtinctionV1 | Domain::StopCompletionV1 => {
            if body.manager.is_none() || body.positive_extinction != Some(true)
                || body.hook.is_some() || body.attempt_id.is_some()
                || (domain == Domain::StopCompletionV1) != body.old_release_hash.as_ref().is_some_and(|h|is_hex_64(h)) {
                return Err("invalid scoped outcome");
            }
        }
        Domain::CreateAdmissionV1 | Domain::ReleaseV1 => {
            // Typed for the later gated profile, with no shipped dispatch or
            // executable release arm in this source slice.
            if body.hook.is_some() || body.attempt_id.is_some() {return Err("invalid launch receipt");}
        }
    }
    let json = serde_json::to_vec(body).map_err(|_| "cannot serialize receipt")?;
    if json.len() > MAX_RECEIPT_BYTES {
        return Err("receipt too large");
    }
    let mut bytes = domain.tag().as_bytes().to_vec();
    bytes.extend_from_slice(&json);
    Ok(bytes)
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub fn sign(
    domain: Domain,
    body: ReceiptBody,
    key: &SigningKey,
) -> Result<SignedReceipt, &'static str> {
    let bytes = signing_bytes(domain, &body)?;
    Ok(SignedReceipt {
        domain,
        key_id: key_id(&key.verifying_key()),
        body,
        signature: hex::encode(key.sign(&bytes).to_bytes()),
    })
}

pub fn verify(
    receipt: &SignedReceipt,
    domain: Domain,
    key: &VerifyingKey,
) -> Result<(), &'static str> {
    if receipt.domain != domain || receipt.key_id != key_id(key) {
        return Err("wrong domain or key");
    }
    let bytes = signing_bytes(domain, &receipt.body)?;
    let signature: [u8; 64] = hex::decode(&receipt.signature)
        .map_err(|_| "bad signature")?
        .try_into()
        .map_err(|_| "bad signature length")?;
    crate::crypto::parse_strict_verifying_key(key.as_bytes())
        .map_err(|_| "bad authority public key")?
        .verify_strict(&bytes, &Signature::from_bytes(&signature))
        .map_err(|_| "invalid signature")
}

#[cfg(unix)]
pub fn read_custodied_file(
    path: &std::path::Path,
    uid: u32,
    gids: &[u32],
    mode: u32,
    limit: usize,
) -> std::io::Result<Vec<u8>> {
    use std::os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    };
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file()
        || meta.uid() != uid
        || !gids.contains(&meta.gid())
        || (meta.mode() & 0o7777) != mode
        || meta.len() as usize > limit
        || meta.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe custody",
        ));
    }
    let _ = file.as_raw_fd();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized file",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domains_and_pins_do_not_alias() {
        let g = Generation {
            boot_id: "b".into(),
            daemon_invocation: "i".into(),
            fortress_id: "abcd1234".into(),
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
        let mut g = g;
        g.unit_name = deterministic_unit_name(&g);
        let body = ReceiptBody {
            generation: g,
            manager: None,
            hook: None,
            attempt_id: None,
            attempted_scope: None,
            candidate_uids: Vec::new(),
            old_release_hash: None,
            positive_extinction: None,
        };
        let key = SigningKey::from_bytes(&[7; 32]);
        let r = sign(Domain::ReleaseV1, body, &key).unwrap();
        assert!(verify(&r, Domain::ReleaseV1, &key.verifying_key()).is_ok());
        assert!(verify(&r, Domain::ReleasedUnresolvedV1, &key.verifying_key()).is_err());
        let other = SigningKey::from_bytes(&[8; 32]);
        assert!(verify(&r, Domain::ReleaseV1, &other.verifying_key()).is_err());
        let pins = Pins {
            schema: 1,
            algorithm: "ed25519".into(),
            admission_public: hex::encode([0u8; 32]),
            admission_key_id: hex::encode(Sha256::digest([0u8; 32])),
            completion_public: hex::encode(other.verifying_key().as_bytes()),
            completion_key_id: key_id(&other.verifying_key()),
        };
        assert!(pins.validate().is_err(), "weak authority keys must not pin");
    }
}
