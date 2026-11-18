//! Bounded ordinary checkpoint evidence. Only the authenticated wall may supply this report.
use super::{
    activation_anchor as anchor, append_contract, drain_store, frame, records,
    signer_client::StatusReply, signer_contract, writer_peer::NS_PER_MS, writer_protocol,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CHECKPOINT_PENDING_MAX: usize = 1;
pub const CHECKPOINT_CHALLENGE_MS: u64 = drain_store::D_REQUEST_DEADLINE_MS as u64
    + 2 * signer_contract::SIGNER_REQUEST_DEADLINE_MS as u64;
pub const CHECKPOINT_AGE_MS: u64 = signer_contract::SIGNER_REQUEST_DEADLINE_MS as u64;
/// Wall clients retain an in-window checkpoint acknowledgement through final delivery.
// Must match writer_service::CHECKPOINT_ADJUDICATION_BUDGET_MS and the serve poll tick:
// an in-window grant may reach W after adjudication and one relative sleep.
pub const CHECKPOINT_ACK_MS: u64 = CHECKPOINT_CHALLENGE_MS
    + super::writer_service::CHECKPOINT_ADJUDICATION_BUDGET_MS
    + super::signer_watchdog::WATCHDOG_TICK_MS as u64;
pub const CHECKPOINT_PART_SILENCE_MS: u64 = CHECKPOINT_AGE_MS;
// Generated from the same closed field tables used by the two parsers.
include!("checkpoint_bounds.rs");
pub const CHECKPOINT_PARTS_MAX: usize = CHECKPOINT_HONEST_MAX_BYTES.div_ceil(anchor::MAX_BYTES);
pub const CHECKPOINT_MAX_BYTES: usize = CHECKPOINT_PARTS_MAX * anchor::MAX_BYTES;
pub const CHECKPOINT_PART_PACKET_MAX_BYTES: usize =
    frame::LENGTH_BYTES + CHECKPOINT_PART_HEADER_MAX_BYTES + anchor::MAX_BYTES;
const _: () = assert!(CHECKPOINT_HONEST_MAX_BYTES <= 6 * anchor::MAX_BYTES);
const _: () = assert!(CHECKPOINT_PART_PACKET_MAX_BYTES <= signer_contract::SIGNER_FRAME_MAX_BYTES);
const _: () = assert!(
    frame::LENGTH_BYTES
        + CHECKPOINT_CHALLENGE_HEADER_MAX_BYTES
        + writer_protocol::WRITER_STATUS_MAX_BYTES
        <= writer_protocol::WRITER_REPLY_PACKET_MAX_BYTES
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Shape,
    Echo,
    Digest,
    Order,
    Expired,
    Freshness,
    Observation,
    Conflict,
}
pub type Result<T> = std::result::Result<T, Refusal>;
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
pub fn status_bytes(status: &StatusReply) -> Result<Vec<u8>> {
    crate::smb::jcs::encode(&serde_json::to_value(status).map_err(|_| Refusal::Shape)?)
        .map(String::into_bytes)
        .map_err(|_| Refusal::Shape)
}

/// Locate original object bytes after canonical admission; never reserialize a join state.
fn object_bytes<'a>(bytes: &'a [u8], marker: &[u8]) -> Result<&'a [u8]> {
    let start = bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .map(|n| n + marker.len() - 1)
        .ok_or(Refusal::Shape)?;
    let mut depth = 0usize;
    let mut string = false;
    let mut escaped = false;
    for (offset, &byte) in bytes[start..].iter().enumerate() {
        if string {
            if byte == b'"' && !escaped {
                string = false;
            }
            escaped = byte == b'\\' && !escaped;
        } else {
            match byte {
                b'"' => string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.checked_sub(1).ok_or(Refusal::Shape)?;
                    if depth == 0 {
                        return Ok(&bytes[start..=start + offset]);
                    }
                }
                _ => {}
            }
        }
    }
    Err(Refusal::Shape)
}

/// Required ordinary verifier for the writer's authenticated checkpoint path.
/// It retains no report, so a later heartbeat cannot promote stale evidence.
pub struct OrdinaryCheckpointProvider {
    _sealed: (),
}
impl OrdinaryCheckpointProvider {
    /// Construct the evidence-checking provider, with no synthetic acceptance mode.
    pub fn production() -> Self {
        Self { _sealed: () }
    }
    /// Assemble one challenge-bound report from authenticated D and durable WAL readbacks.
    /// Call on the store worker; WriterClient retains and sends the returned bytes without reserialization.
    pub fn report(
        &self,
        challenge: &super::append_clients::CheckpointChallenge,
        drain: &super::append_clients::DrainObservation,
        wal: super::business_wal::OrdinaryWalCheckpoint,
        fortress: &str,
        revision: u64,
        now: u64,
    ) -> Result<Vec<u8>> {
        let value = serde_json::json!({"version":1,"session_id":challenge.session,
            "request_id":challenge.request,"nonce":challenge.nonce,
            "status_digest":digest(&status_bytes(&challenge.status)?),
            "observed_boottime_ns":drain.observed().min(wal.observed).to_string(),
            "fortress_id":fortress,"enrollment_revision":revision,
            "d_observation":drain.value(),"wal_checkpoint":wal.value});
        let bytes = records::canonical_integer_domain(&value).ok_or(Refusal::Shape)?;
        let report = Candidate::parse(&bytes)?;
        report.fresh(challenge.issued, now)?;
        self.verify(&report, &challenge.status, fortress, revision)?;
        Ok(bytes)
    }
    pub(crate) fn verify(
        &self,
        report: &Candidate,
        status: &StatusReply,
        fortress: &str,
        revision: u64,
    ) -> Result<()> {
        report.consistent(status, fortress, revision)
    }
}

pub struct Candidate {
    value: Value,
    pub observed: u64,
}
impl Candidate {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > CHECKPOINT_MAX_BYTES {
            return Err(Refusal::Shape);
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|_| Refusal::Shape)?;
        // Must match parseBusinessCheckpoint: retain original numeric spellings at the raw join boundary.
        let wal = object_bytes(bytes, b"\"wal_checkpoint\":{")?;
        let raw_join = object_bytes(wal, b"\"join_state\":{")?;
        let join = records::decode_join_state(raw_join).ok_or(Refusal::Shape)?;
        if value["wal_checkpoint"]["join_state"] != join
            || !append_contract::shape("checkpoint", &value)
        {
            return Err(Refusal::Shape);
        }
        // The validated checkpoint has the same closed ASCII/integer domain as its join state.
        // Comparing the complete original bytes also refuses duplicate keys and noncanonical escaping.
        if records::canonical_integer_domain(&value).as_deref() != Some(bytes) {
            return Err(Refusal::Shape);
        }
        let observed = value["observed_boottime_ns"]
            .as_str()
            .and_then(writer_protocol::canonical_deadline)
            .ok_or(Refusal::Shape)?;
        Ok(Self { value, observed })
    }
    pub fn echo(&self, session: &str, request: &str, nonce: &str) -> Result<()> {
        if self.value["session_id"] != session
            || self.value["request_id"] != request
            || self.value["nonce"] != nonce
        {
            return Err(Refusal::Echo);
        }
        Ok(())
    }
    // observed_boottime_ns is W's self-report, not a measurement by P. P verifies
    // only issued <= observed <= now and the 1,000 ms age before consuming freshness.
    pub fn fresh(&self, issued: u64, now: u64) -> Result<()> {
        if now
            .checked_sub(issued)
            .filter(|age| *age < CHECKPOINT_CHALLENGE_MS * NS_PER_MS)
            .is_none()
        {
            return Err(Refusal::Expired);
        }
        if self.observed < issued
            || now
                .checked_sub(self.observed)
                .filter(|age| *age <= CHECKPOINT_AGE_MS * NS_PER_MS)
                .is_none()
        {
            return Err(Refusal::Freshness);
        }
        Ok(())
    }
    /// S authenticates its grant; the admitted W owns D and WAL observations. No D transcript is inferred.
    pub fn consistent(&self, status: &StatusReply, fortress: &str, revision: u64) -> Result<()> {
        let v = &self.value;
        let d = &v["d_observation"];
        let a = &d["anchor"];
        let w = &v["wal_checkpoint"];
        let j = &w["join_state"];
        if status.state != "UNLOCKED"
            || v["fortress_id"] != fortress
            || v["enrollment_revision"] != revision
            || a["fortress_id"] != fortress
            || a["enrollment_revision"] != revision
            || status.anchor_revision != Some(revision)
            || status.anchor_digest.as_deref() != d["anchor_digest"].as_str()
            || v["status_digest"] != digest(&status_bytes(status)?)
            || d["state"] != "PRESENT"
            || d["latched"] != false
            || d["uncertain"] != false
            || a["retired"] != false
            || a["recovery_required"] != false
            || !a["transaction_id"].is_null()
            || a["reserved_sequence"] != a["committed_sequence"]
            || !a["reserved_body_digest"].is_null()
            || w["unresolved_intent"] != false
        {
            return Err(Refusal::Observation);
        }
        let grant = serde_json::to_value(&status.grant).map_err(|_| Refusal::Shape)?;
        for key in ["role", "machine_id", "activation_id"] {
            if a[key] != grant[key] {
                return Err(Refusal::Observation);
            }
        }
        if a["generation_high_water"] != grant["generation"] || a["boot_id"] != status.boot_id {
            return Err(Refusal::Observation);
        }
        for key in [
            "role",
            "epoch",
            "kid",
            "public_key",
            "identity_id",
            "machine_id",
        ] {
            if j["pin"][key] != grant[key] {
                return Err(Refusal::Observation);
            }
        }
        for key in ["activation_id", "lease_id", "generation"] {
            if j["grant"][key] != grant[key] {
                return Err(Refusal::Observation);
            }
        }
        if j["grant"]["boot_id"] != status.boot_id
            || j["grant"]["expires_ns"] != status.expires_boottime_ns
        {
            return Err(Refusal::Observation);
        }
        for key in [
            "committed_sequence",
            "committed_digest",
            "drained_sequence",
            "drained_digest",
        ] {
            if w[key] != a[key] {
                return Err(Refusal::Observation);
            }
        }
        if j["anchor"]["sequence"] != w["committed_sequence"]
            || j["anchor"]["commitment"] != w["committed_digest"]
        {
            return Err(Refusal::Observation);
        }
        let committed = a["committed_sequence"].as_u64().ok_or(Refusal::Shape)?;
        let drained = a["drained_sequence"].as_u64().ok_or(Refusal::Shape)?;
        let rows = w["retained_originals"].as_array().ok_or(Refusal::Shape)?;
        if committed.checked_sub(drained) != Some(rows.len() as u64) {
            return Err(Refusal::Observation);
        }
        for (i, row) in rows.iter().enumerate() {
            if drained.checked_add(i as u64 + 1) != row["sequence"].as_u64() {
                return Err(Refusal::Observation);
            }
        }
        if let Some(last) = rows.last() {
            if last["commitment"] != w["committed_digest"] {
                return Err(Refusal::Observation);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub request_id: String,
    pub nonce: String,
    pub part_index: usize,
    pub part_count: usize,
    pub total_length: usize,
    pub checkpoint_digest: String,
}
impl Part {
    pub fn valid(&self, payload: usize) -> bool {
        self.total_length > 0
            && self.total_length <= CHECKPOINT_MAX_BYTES
            && self.part_count == self.total_length.div_ceil(anchor::MAX_BYTES)
            && self.part_index < self.part_count
            && payload
                == if self.part_index + 1 == self.part_count {
                    self.total_length - self.part_index * anchor::MAX_BYTES
                } else {
                    anchor::MAX_BYTES
                }
            && super::drain_protocol::id(&self.request_id)
            && super::drain_protocol::id(&self.nonce)
            && super::drain_protocol::digest(&self.checkpoint_digest)
    }
}
pub struct Transfer {
    first: Part,
    next: usize,
    bytes: Vec<u8>,
    hashes: Vec<String>,
    last_part: u64,
}
impl Transfer {
    pub fn begin(part: &Part, now: u64) -> Result<Self> {
        if part.part_index != 0
            || !part.valid(if part.part_count == 1 {
                part.total_length
            } else {
                anchor::MAX_BYTES
            })
        {
            return Err(Refusal::Order);
        }
        Ok(Self {
            first: part.clone(),
            next: 0,
            bytes: Vec::with_capacity(part.total_length),
            hashes: Vec::with_capacity(part.part_count),
            last_part: now,
        })
    }
    pub fn expired(&self, issued: u64, now: u64) -> bool {
        now.saturating_sub(issued) >= CHECKPOINT_CHALLENGE_MS * NS_PER_MS
            || now.saturating_sub(self.last_part) >= CHECKPOINT_PART_SILENCE_MS * NS_PER_MS
    }
    pub fn push(&mut self, part: &Part, payload: &[u8], packet: &[u8], now: u64) -> Result<bool> {
        if !part.valid(payload.len())
            || part.part_index != self.next
            || part.request_id != self.first.request_id
            || part.nonce != self.first.nonce
            || part.part_count != self.first.part_count
            || part.total_length != self.first.total_length
            || part.checkpoint_digest != self.first.checkpoint_digest
        {
            return Err(Refusal::Order);
        }
        self.bytes.extend_from_slice(payload);
        self.hashes.push(digest(packet));
        self.next += 1;
        self.last_part = now;
        Ok(self.next == self.first.part_count)
    }
    pub fn finish(self) -> Result<(Vec<u8>, Vec<String>)> {
        if self.next != self.first.part_count || digest(&self.bytes) != self.first.checkpoint_digest
        {
            return Err(Refusal::Digest);
        }
        Ok((self.bytes, self.hashes))
    }
}
