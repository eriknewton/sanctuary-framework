//! The wall imports this codec; must match the K1c-2e wall side.
use super::{records, signer_client, signer_contract::*, signer_service};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const WRITER_PROTOCOL: &str = "sanctuary.business-writer.v1";
pub const LENGTH_BYTES: usize = 4; // u32be header length.
pub const WRITER_HEADER_MAX_BYTES: usize = SIGNER_HEADER_MAX_BYTES;
pub const WRITER_ENVELOPE_MAX_BYTES: usize = 4096; // Design envelope, including wrapper.
pub const WRITER_STATUS_MAX_BYTES: usize = 4096; // Design STATUS payload cap.
pub const WRITER_SIGN_PACKET_MAX_BYTES: usize =
    LENGTH_BYTES + WRITER_HEADER_MAX_BYTES + SIGNER_PREIMAGE_MAX_BYTES;
pub const WRITER_REPLY_PACKET_MAX_BYTES: usize =
    LENGTH_BYTES + WRITER_HEADER_MAX_BYTES + WRITER_ENVELOPE_MAX_BYTES;
pub const WRITER_CONNECTIONS_MAX: usize = 2; // Bound wall and terminal second accept.
pub const WRITER_WORK_MAX: usize = 1; // One synchronous signer slot.
pub const WRITER_QUEUE_MAX: usize = 0; // No queued signing authority.
pub const WRITER_HEARTBEAT_MS: u64 = SIGNER_IDLE_DEADLINE_MS as u64 / 4;
pub const WRITER_SIGN_DEADLINE_MAX_MS: u64 = SIGNER_IDLE_DEADLINE_MS as u64 - WRITER_HEARTBEAT_MS;
pub const WRITER_HANDSHAKE_DEADLINE_MS: u64 = SIGNER_HANDSHAKE_DEADLINE_MS as u64;
pub const SESSION_ID_BYTES: usize = 16; // Fresh 128-bit identifier.
pub const SIGNATURE_BYTES: usize = 64; // Ed25519 signature width.
pub const SIGNATURE_TEXT_BYTES: usize = (SIGNATURE_BYTES * 8).div_ceil(6); // Unpadded base64url, 86 bytes.
const _: () = assert!(WRITER_SIGN_PACKET_MAX_BYTES == SIGNER_FRAME_MAX_BYTES);
const _: () = assert!(WRITER_STATUS_MAX_BYTES >= signer_service::RESPONSE_MAX_BYTES);
const _: () = assert!(
    WRITER_REPLY_PACKET_MAX_BYTES
        >= LENGTH_BYTES + WRITER_HEADER_MAX_BYTES + WRITER_STATUS_MAX_BYTES
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Length,
    Canonical,
    Schema,
    Direction,
    Session,
    Handshake,
    Envelope,
    Transport,
}
pub type Result<T> = std::result::Result<T, Refusal>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToWriter,
    ToWall,
}
impl Direction {
    pub fn cap(self) -> usize {
        match self {
            Self::ToWriter => WRITER_SIGN_PACKET_MAX_BYTES,
            Self::ToWall => WRITER_REPLY_PACKET_MAX_BYTES,
        }
    }
}
#[derive(Debug)]
pub enum Operation {
    Hello,
    HelloAck,
    Status { request_id: String },
    StatusReply { request_id: String },
    Sign(signer_service::Header),
    Verified { request_id: String },
    Refused { request_id: String },
}
#[derive(Debug)]
pub struct Frame<'a> {
    pub operation: Operation,
    pub payload: &'a [u8],
}
fn id(text: &str) -> bool {
    text.len() == SESSION_ID_BYTES * 2
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn exact(value: &Value, extra: &[&str]) -> bool {
    const COMMON: &[&str] = &["v", "protocol", "op", "session_id"];
    value.as_object().is_some_and(|obj| {
        obj.len() == COMMON.len() + extra.len()
            && COMMON.iter().chain(extra).all(|key| obj.contains_key(*key))
    })
}
fn request(value: &Value) -> Result<String> {
    let text = value["request_id"].as_str().ok_or(Refusal::Schema)?;
    if !id(text) {
        return Err(Refusal::Schema);
    }
    Ok(text.to_owned())
}
fn payload_length(value: &Value, field: &str, max: usize) -> Result<usize> {
    let length = value[field]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(Refusal::Length)?;
    if length > max {
        return Err(Refusal::Length);
    }
    Ok(length)
}
/// Decode only the direction selected before receipt, retaining the immutable payload slice.
pub fn decode<'a>(packet: &'a [u8], direction: Direction, session: &str) -> Result<Frame<'a>> {
    // Directional caps bound work before any JSON is parsed.
    if packet.len() < LENGTH_BYTES || packet.len() > direction.cap() {
        return Err(Refusal::Length);
    }
    let length = u32::from_be_bytes(
        packet[..LENGTH_BYTES]
            .try_into()
            .map_err(|_| Refusal::Length)?,
    ) as usize;
    let end = LENGTH_BYTES.checked_add(length).ok_or(Refusal::Length)?;
    if length > WRITER_HEADER_MAX_BYTES || end > packet.len() {
        return Err(Refusal::Length);
    }
    let value = signer_service::canonical(&packet[LENGTH_BYTES..end], WRITER_HEADER_MAX_BYTES)
        .map_err(|_| Refusal::Canonical)?;
    if value["v"] != 1 || value["protocol"] != WRITER_PROTOCOL {
        return Err(Refusal::Schema);
    }
    // The writer's fresh id binds the ACK and all subsequent traffic to one captured lifetime.
    if !id(session) || value["session_id"].as_str() != Some(session) {
        return Err(Refusal::Session);
    }
    let op = value["op"].as_str().ok_or(Refusal::Schema)?;
    let (operation, payload_len, fields): (Operation, usize, &[&str]) = match (direction, op) {
        (Direction::ToWall, "HELLO") => (Operation::Hello, 0, &[]),
        (Direction::ToWriter, "HELLO_ACK") => (Operation::HelloAck, 0, &[]),
        (Direction::ToWriter, "STATUS") => (
            Operation::Status {
                request_id: request(&value)?,
            },
            0,
            &["request_id"],
        ),
        (Direction::ToWall, "STATUS") => (
            Operation::StatusReply {
                request_id: request(&value)?,
            },
            payload_length(&value, "status_length", WRITER_STATUS_MAX_BYTES)?,
            &["request_id", "status_length"],
        ),
        (Direction::ToWall, "VERIFIED") => (
            Operation::Verified {
                request_id: request(&value)?,
            },
            payload_length(&value, "envelope_length", WRITER_ENVELOPE_MAX_BYTES)?,
            &["request_id", "envelope_length"],
        ),
        (Direction::ToWall, "REFUSED") => (
            Operation::Refused {
                request_id: request(&value)?,
            },
            0,
            &["request_id"],
        ),
        (Direction::ToWriter, "SIGN") => {
            let fields = &[
                "request_id",
                "activation_id",
                "lease_id",
                "generation",
                "epoch",
                "role",
                "deadline_boottime_ns",
                "preimage_length",
            ];
            if !exact(&value, fields) {
                return Err(Refusal::Schema);
            }
            let mut signer = value.clone();
            let map = signer.as_object_mut().ok_or(Refusal::Schema)?;
            map.remove("op");
            map.remove("session_id");
            map.insert("protocol".into(), json!(SIGNER_PROTOCOL));
            let encoded =
                signer_service::encode(&signer, &packet[end..]).map_err(|_| Refusal::Length)?;
            let (header, _) = signer_service::decode(&encoded).map_err(|_| Refusal::Schema)?;
            let size = header.preimage_length;
            (Operation::Sign(header), size, fields)
        }
        (_, "HELLO" | "HELLO_ACK" | "SIGN" | "VERIFIED" | "REFUSED") => {
            return Err(Refusal::Direction)
        }
        _ => return Err(Refusal::Schema),
    };
    if !exact(&value, fields) {
        return Err(Refusal::Schema);
    }
    // Equality rejects trailing bytes as well as short payloads; no second record can hide in a packet.
    if end.checked_add(payload_len) != Some(packet.len()) {
        return Err(Refusal::Length);
    }
    match &operation {
        Operation::StatusReply { .. } => {
            StatusPayload::decode(&packet[end..])?;
        }
        Operation::Verified { .. } => {
            decode_envelope(&packet[end..])?;
        }
        _ => {}
    }
    Ok(Frame {
        operation,
        payload: &packet[end..],
    })
}
/// Encode through the same decoder used by the receiving side.
pub fn encode(
    direction: Direction,
    session: &str,
    operation: &Operation,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut value = json!({"v": 1, "protocol": WRITER_PROTOCOL, "session_id": session});
    let (op, request_id) = match operation {
        Operation::Hello => ("HELLO", None),
        Operation::HelloAck => ("HELLO_ACK", None),
        Operation::Status { request_id } => ("STATUS", Some(request_id)),
        Operation::StatusReply { request_id } => {
            value["status_length"] = json!(payload.len());
            ("STATUS", Some(request_id))
        }
        Operation::Verified { request_id } => {
            value["envelope_length"] = json!(payload.len());
            ("VERIFIED", Some(request_id))
        }
        Operation::Refused { request_id } => ("REFUSED", Some(request_id)),
        Operation::Sign(h) => {
            value["activation_id"] = json!(h.activation_id);
            value["lease_id"] = json!(h.lease_id);
            value["generation"] = json!(h.generation);
            value["epoch"] = json!(h.epoch);
            value["role"] = json!(h.role);
            value["deadline_boottime_ns"] = json!(h.deadline_boottime_ns);
            value["preimage_length"] = json!(h.preimage_length);
            ("SIGN", Some(&h.request_id))
        }
    };
    value["op"] = json!(op);
    if let Some(request_id) = request_id {
        value["request_id"] = json!(request_id);
    }
    let bytes = signer_service::encode(&value, payload).map_err(|_| Refusal::Length)?;
    decode(&bytes, direction, session)?;
    Ok(bytes)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    AwaitingAck,
    Established,
    Closed,
}
pub struct Handshake {
    session: String,
    state: HandshakeState,
}
impl Handshake {
    pub fn new(session: String) -> Result<Self> {
        if !id(&session) {
            return Err(Refusal::Session);
        }
        Ok(Self {
            session,
            state: HandshakeState::AwaitingAck,
        })
    }
    pub fn hello(&self) -> Result<Vec<u8>> {
        if self.state != HandshakeState::AwaitingAck {
            return Err(Refusal::Handshake);
        }
        encode(Direction::ToWall, &self.session, &Operation::Hello, &[])
    }
    pub fn state(&self) -> HandshakeState {
        self.state
    }
    pub fn receive<'a>(&mut self, packet: &'a [u8]) -> Result<Frame<'a>> {
        let result = self.admit(packet);
        if result.is_err() {
            self.state = HandshakeState::Closed;
        }
        result
    }
    fn admit<'a>(&mut self, packet: &'a [u8]) -> Result<Frame<'a>> {
        let frame = decode(packet, Direction::ToWriter, &self.session)?;
        match (self.state, &frame.operation) {
            (HandshakeState::AwaitingAck, Operation::HelloAck) => {
                self.state = HandshakeState::Established
            }
            (HandshakeState::Established, Operation::Status { .. } | Operation::Sign(_)) => {}
            _ => return Err(Refusal::Handshake),
        }
        Ok(frame)
    }
}
/// STATUS uses S's state string; must match the grant object in signer_status_vectors.json.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatusPayload {
    pub state: String,
    pub grant: Option<signer_client::CurrentGrantView>,
    pub started_boottime_ns: String,
    pub expires_boottime_ns: String,
    pub boot_id: String,
    pub anchor_revision: Option<u64>,
    pub anchor_digest: Option<String>,
}
impl StatusPayload {
    pub fn from_signer(view: &signer_client::StatusReply, granted: bool) -> Self {
        Self {
            state: view.state.clone(),
            grant: granted.then(|| view.grant.clone()),
            started_boottime_ns: view.started_boottime_ns.clone(),
            expires_boottime_ns: view.expires_boottime_ns.clone(),
            boot_id: view.boot_id.clone(),
            anchor_revision: view.anchor_revision,
            anchor_digest: view.anchor_digest.clone(),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self).map_err(|_| Refusal::Schema)?;
        let bytes = crate::smb::jcs::encode(&value)
            .map_err(|_| Refusal::Canonical)?
            .into_bytes();
        Self::decode(&bytes)?;
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value = signer_service::canonical(bytes, WRITER_STATUS_MAX_BYTES)
            .map_err(|_| Refusal::Canonical)?;
        let fields = [
            "state",
            "grant",
            "started_boottime_ns",
            "expires_boottime_ns",
            "boot_id",
            "anchor_revision",
            "anchor_digest",
        ];
        if !value
            .as_object()
            .is_some_and(|m| m.len() == fields.len() && fields.iter().all(|k| m.contains_key(*k)))
        {
            return Err(Refusal::Schema);
        }
        let status: Self = serde_json::from_value(value.clone()).map_err(|_| Refusal::Schema)?;
        // Closed STATUS has no grant authority; shared S parsing still validates every metadata field.
        let corpus: Value = serde_json::from_str(include_str!("signer_status_vectors.json"))
            .map_err(|_| Refusal::Schema)?;
        let schema = &corpus["schema"];
        if !schema["states"]
            .as_array()
            .is_some_and(|states| states.contains(&value["state"]))
            || !id(&status.boot_id)
            || [&status.started_boottime_ns, &status.expires_boottime_ns]
                .iter()
                .any(|s| s.parse::<u64>().map_or(true, |n| n.to_string() != **s))
            || status.anchor_revision.is_some() != status.anchor_digest.is_some()
            || status
                .anchor_revision
                .is_some_and(|n| n == 0 || n > (1u64 << 53) - 1)
            || status.anchor_digest.as_ref().is_some_and(|s| {
                !s.strip_prefix("sha256:").is_some_and(|s| {
                    s.len() == 32 * 2
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            })
        {
            return Err(Refusal::Schema);
        }
        if status.grant.is_some() {
            let mut signer = value;
            signer["op"] = json!("STATUS");
            let packet = signer_service::encode(&signer, &[]).map_err(|_| Refusal::Schema)?;
            signer_client::parse_status_packet(&packet).map_err(|_| Refusal::Schema)?;
            if status.state != "UNLOCKED" {
                return Err(Refusal::Schema);
            }
        }
        Ok(status)
    }
}
/// Measure with the record vectors' exact signature width before admitting SIGN.
pub fn measured_envelope(body: &[u8]) -> Result<usize> {
    Ok(envelope(body, &[0; SIGNATURE_BYTES])?.len())
}
/// Insert only the signature; the body must re-encode to the frozen input bytes.
pub fn envelope(body: &[u8], signature: &[u8; SIGNATURE_BYTES]) -> Result<Vec<u8>> {
    let value = records::decode(body).ok_or(Refusal::Canonical)?;
    // Must match the outer-index rule in records::advance.
    let mut outer = serde_json::Map::new();
    for key in LINUX_FIELDS
        .iter()
        .copied()
        .filter(|key| !key.ends_with("_digest"))
        .chain(std::iter::once("machine_id"))
    {
        outer.insert(
            key.to_owned(),
            value.get(key).ok_or(Refusal::Envelope)?.clone(),
        );
    }
    let text = URL_SAFE_NO_PAD.encode(signature);
    if text.len() != SIGNATURE_TEXT_BYTES {
        return Err(Refusal::Envelope);
    }
    outer.insert("signature".into(), json!(text));
    let wrapped = json!({"body": value, "outer": outer});
    if crate::smb::jcs::encode(&wrapped["body"])
        .map_err(|_| Refusal::Canonical)?
        .as_bytes()
        != body
    {
        return Err(Refusal::Envelope);
    }
    let bytes = crate::smb::jcs::encode(&wrapped)
        .map_err(|_| Refusal::Canonical)?
        .into_bytes();
    if !envelope_fits(bytes.len()) {
        return Err(Refusal::Envelope);
    }
    Ok(bytes)
}

/// Transport refuses rights and any truncated or unrecognized ancillary data before decoding.
pub fn receive(fd: std::os::fd::RawFd, direction: Direction) -> Result<super::signer_peer::Packet> {
    let packet =
        super::signer_peer::receive(fd, direction.cap()).map_err(|_| Refusal::Transport)?;
    if !packet.rights.is_empty() {
        return Err(Refusal::Transport);
    }
    Ok(packet)
}
/// Validate the exact canonical envelope shape without conferring signature authority.
pub fn decode_envelope(bytes: &[u8]) -> Result<Value> {
    let value = signer_service::canonical(bytes, WRITER_ENVELOPE_MAX_BYTES)
        .map_err(|_| Refusal::Canonical)?;
    let signature: [u8; SIGNATURE_BYTES] = URL_SAFE_NO_PAD
        .decode(
            value["outer"]["signature"]
                .as_str()
                .ok_or(Refusal::Envelope)?,
        )
        .map_err(|_| Refusal::Envelope)?
        .try_into()
        .map_err(|_| Refusal::Envelope)?;
    let body = crate::smb::jcs::encode(&value["body"]).map_err(|_| Refusal::Canonical)?;
    if envelope(body.as_bytes(), &signature)? != bytes {
        return Err(Refusal::Envelope);
    }
    Ok(value)
}

fn envelope_fits(length: usize) -> bool {
    length <= WRITER_ENVELOPE_MAX_BYTES
}
#[cfg(feature = "test-isolation")]
pub fn envelope_size_admitted_for_test(length: usize) -> bool {
    envelope_fits(length)
}
