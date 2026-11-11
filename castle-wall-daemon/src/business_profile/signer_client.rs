//! Direct signer transport for the future writer, which is its only production consumer.
//! There is no production caller in this slice and binding grants no installed-business authority.
use super::{
    custody::CONTROL_ROOT,
    signer_contract::{
        ROLE_REGISTRY, SIGNER_HANDSHAKE_DEADLINE_MS, SIGNER_PREIMAGE_MAX_BYTES, SIGNER_PROTOCOL,
        SIGNER_REQUEST_DEADLINE_MS,
    },
    signer_peer::{self, Peer, PeerPolicy},
    signer_service::{self, Header, LENGTH_BYTES, RESPONSE_MAX_BYTES, SIGN_SOCKET},
    signer_watchdog::boottime_ns,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io,
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
const NS_PER_MS: u64 = 1_000_000; // Nanoseconds in one millisecond.
const ID_HEX_CHARS: usize = 16 * 2; // The protocol's 128-bit identifier encoded as hex.
const DIGEST_HEX_CHARS: usize = 32 * 2; // SHA-256 bytes encoded as hex.
const SIGNATURE_BYTES: usize = 64; // Ed25519 signature width.
const PUBLIC_KEY_BYTES: usize = 32; // Ed25519 compressed point width.
const SAFE_INTEGER_MAX: u64 = (1u64 << 53) - 1; // Integers represented exactly by both JSON runtimes.
type Clock = Arc<dyn Fn() -> io::Result<u64> + Send + Sync>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerClientState {
    Unbound,
    Bound,
    Settling,
    Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Policy,
    Transport,
    Rights,
    Peer,
    Length,
    Trailing,
    Canonical,
    Schema,
    Refused,
    Unmatched,
    DuplicateReply,
    Deadline,
    State,
    Busy,
    Grant,
    Expired,
    Preimage,
    Header,
    Signature,
}
pub type Result<T> = std::result::Result<T, Refusal>;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CurrentGrantView {
    pub role: String,
    pub epoch: u64,
    pub public_key: String,
    pub kid: String,
    pub identity_id: String,
    pub machine_id: String,
    pub activation_id: String,
    pub lease_id: String,
    pub generation: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatusReply {
    pub op: String,
    pub state: String,
    pub grant: CurrentGrantView,
    pub started_boottime_ns: String,
    pub expires_boottime_ns: String,
    pub boot_id: String,
    pub anchor_revision: Option<u64>,
    pub anchor_digest: Option<String>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct SignedReply {
    pub request_id: String,
    pub kid: String,
    pub signature: [u8; SIGNATURE_BYTES],
}
fn hex_text(value: &Value, prefix: &str, length: usize) -> bool {
    value
        .as_str()
        .and_then(|text| text.strip_prefix(prefix))
        .is_some_and(|text| {
            text.len() == length
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn u64_text(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.parse::<u64>()
            .is_ok_and(|number| number.to_string() == text)
    })
}
fn object_fields(value: &Value, fields: &Value, schema: &Value) -> bool {
    match (value.as_object(), fields.as_object()) {
        // Exact key equality prevents an unrecognized authority field from reaching readiness.
        (Some(value), Some(fields)) => {
            value.len() == fields.len()
                && fields.iter().all(|(name, kind)| {
                    value
                        .get(name)
                        .is_some_and(|value| typed(value, kind.as_str().unwrap_or(""), schema))
                })
        }
        _ => false,
    }
}
fn typed(value: &Value, kind: &str, schema: &Value) -> bool {
    match kind {
        "StatusOp" => value == "STATUS",
        "State" => schema["states"]
            .as_array()
            .is_some_and(|states| states.contains(value)),
        "Grant" => object_fields(value, &schema["grant_fields"], schema),
        "Role" => ROLE_REGISTRY
            .iter()
            .any(|entry| value.as_str() == Some(entry.0)),
        "Point" => value.as_str().is_some_and(|text| {
            URL_SAFE_NO_PAD.decode(text).is_ok_and(|bytes| {
                bytes.len() == PUBLIC_KEY_BYTES
                    && URL_SAFE_NO_PAD.encode(&bytes) == text
                    && super::strict_point(&bytes)
            })
        }),
        "N" | "Pos" => value
            .as_u64()
            .is_some_and(|number| number <= SAFE_INTEGER_MAX && (kind == "N" || number > 0)),
        "U64" => u64_text(value),
        "ID" => hex_text(value, "", ID_HEX_CHARS),
        "Kid" => hex_text(value, "k1:sha256:", DIGEST_HEX_CHARS),
        "Digest" => hex_text(value, "sha256:", DIGEST_HEX_CHARS),
        "NullablePos" => value.is_null() || typed(value, "Pos", schema),
        "NullableDigest" => value.is_null() || typed(value, "Digest", schema),
        _ => false,
    }
}
fn packet_value(packet: &[u8]) -> Result<Value> {
    if packet.len() < LENGTH_BYTES {
        return Err(Refusal::Length);
    }
    let length = u32::from_be_bytes(
        packet[..LENGTH_BYTES]
            .try_into()
            .map_err(|_| Refusal::Length)?,
    ) as usize;
    if length > RESPONSE_MAX_BYTES || packet.len() < length + LENGTH_BYTES {
        return Err(Refusal::Length);
    }
    if packet.len() != length + LENGTH_BYTES {
        return Err(Refusal::Trailing);
    }
    signer_service::canonical(
        &packet[LENGTH_BYTES..LENGTH_BYTES + length],
        RESPONSE_MAX_BYTES,
    )
    .map_err(|_| Refusal::Canonical)
}
/// Parses the shared typed STATUS packet without creating client or binding authority.
pub fn parse_status_packet(packet: &[u8]) -> Result<StatusReply> {
    parse_status_value(packet_value(packet)?)
}
fn parse_status_value(value: Value) -> Result<StatusReply> {
    // Must match signer_status_vectors.json: both runtime parsers consume its schema, including nested grant fields.
    let corpus: Value = serde_json::from_str(include_str!("signer_status_vectors.json"))
        .map_err(|_| Refusal::Schema)?;
    let schema = &corpus["schema"];
    let pair = schema["anchor_pair"].as_array().ok_or(Refusal::Schema)?;
    if pair.len() != 2
        || !object_fields(&value, &schema["fields"], schema)
        || value[pair[0].as_str().ok_or(Refusal::Schema)?].is_null()
            != value[pair[1].as_str().ok_or(Refusal::Schema)?].is_null()
    {
        return Err(Refusal::Schema);
    }
    serde_json::from_value(value).map_err(|_| Refusal::Schema)
}
pub struct BusinessSignerClient {
    socket: Option<OwnedFd>,
    peer: Option<Peer>,
    state: SignerClientState,
    latest: StatusReply,
    frozen: Option<StatusReply>,
    outstanding: bool,
    settlement_end: Option<Instant>,
    clock: Clock,
}
impl BusinessSignerClient {
    pub fn bootstrap(policy: PeerPolicy) -> Result<Self> {
        Self::bootstrap_inner(
            &Path::new(CONTROL_ROOT).join(SIGN_SOCKET),
            policy,
            Arc::new(boottime_ns),
        )
    }
    #[cfg(feature = "test-isolation")]
    pub fn bootstrap_at(path: &Path, policy: PeerPolicy) -> Result<Self> {
        Self::bootstrap_inner(path, policy, Arc::new(boottime_ns))
    }
    #[cfg(feature = "test-isolation")]
    pub fn bootstrap_at_with_clock(path: &Path, policy: PeerPolicy, clock: Clock) -> Result<Self> {
        Self::bootstrap_inner(path, policy, clock)
    }
    fn bootstrap_inner(path: &Path, policy: PeerPolicy, clock: Clock) -> Result<Self> {
        let end = clock()
            .map_err(|_| Refusal::Transport)?
            .checked_add(SIGNER_HANDSHAKE_DEADLINE_MS as u64 * NS_PER_MS)
            .ok_or(Refusal::Deadline)?;
        let socket = signer_peer::connect(path).map_err(|_| Refusal::Transport)?;
        signer_peer::passcred(socket.as_raw_fd()).map_err(|_| Refusal::Transport)?;
        let peer = Peer::capture(socket.as_raw_fd(), &policy).map_err(|_| Refusal::Policy)?;
        if signer_service::readable(socket.as_raw_fd()) {
            return Err(Refusal::Unmatched);
        }
        signer_peer::send(socket.as_raw_fd(), b"{\"op\":\"STATUS\"}", &[])
            .map_err(|_| Refusal::Transport)?;
        let bytes = Self::receive(
            &socket,
            &peer,
            &clock,
            end,
            Instant::now() + Duration::from_millis(SIGNER_HANDSHAKE_DEADLINE_MS as u64),
        )?;
        let latest = parse_status_packet(&bytes)?;
        if clock().map_err(|_| Refusal::Transport)? >= end {
            return Err(Refusal::Deadline);
        }
        if signer_service::readable(socket.as_raw_fd()) {
            return Err(Refusal::DuplicateReply);
        }
        Ok(Self {
            socket: Some(socket),
            peer: Some(peer),
            state: SignerClientState::Unbound,
            latest,
            frozen: None,
            outstanding: false,
            settlement_end: None,
            clock,
        })
    }
    pub fn state(&self) -> SignerClientState {
        self.state
    }
    pub fn latest_status(&self) -> &StatusReply {
        &self.latest
    }
    fn now(&self) -> Result<u64> {
        (self.clock)().map_err(|_| Refusal::Transport)
    }
    fn fail<T>(&mut self, refusal: Refusal) -> Result<T> {
        // Refusal stops admission before settling retained I/O; no discarded completion can become a signature.
        if self.state != SignerClientState::Closed {
            self.state = SignerClientState::Settling;
        }
        self.settle_io();
        self.socket.take();
        self.peer.take();
        if self.state != SignerClientState::Closed {
            self.state = SignerClientState::Settling;
        }
        Err(refusal)
    }
    pub fn bind(&mut self, expected: &CurrentGrantView) -> Result<()> {
        let result = self.bind_inner(expected);
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }
    fn bind_inner(&mut self, expected: &CurrentGrantView) -> Result<()> {
        if self.state != SignerClientState::Unbound {
            return self.fail(Refusal::State);
        }
        let now = self.now()?;
        if self.latest.state != "UNLOCKED" || &self.latest.grant != expected {
            return self.fail(Refusal::Grant);
        }
        if !Self::live(&self.latest, now) {
            return self.fail(Refusal::Expired);
        }
        // First client bind freezes the authenticated observation without I/O or a renewal opportunity.
        self.frozen = Some(self.latest.clone());
        self.state = SignerClientState::Bound;
        Ok(())
    }
    fn live(view: &StatusReply, now: u64) -> bool {
        match (
            view.started_boottime_ns.parse::<u64>(),
            view.expires_boottime_ns.parse::<u64>(),
        ) {
            (Ok(start), Ok(end)) => now >= start && now < end,
            _ => false,
        }
    }
    fn unchanged(a: &StatusReply, b: &StatusReply) -> bool {
        a.grant == b.grant
            && a.boot_id == b.boot_id
            && a.started_boottime_ns == b.started_boottime_ns
            && a.expires_boottime_ns == b.expires_boottime_ns
    }
    fn receive(
        socket: &OwnedFd,
        peer: &Peer,
        clock: &Clock,
        end: u64,
        wall_end: Instant,
    ) -> Result<Vec<u8>> {
        loop {
            let now = clock().map_err(|_| Refusal::Transport)?;
            if now >= end || Instant::now() >= wall_end {
                return Err(Refusal::Deadline);
            }
            if !peer.live() {
                return Err(Refusal::Peer);
            }
            let remaining = Duration::from_nanos(end - now)
                .min(wall_end.saturating_duration_since(Instant::now()));
            let timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
            let mut poll = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, timeout) } < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(Refusal::Transport);
            }
            if poll.revents == 0 {
                continue;
            }
            let packet =
                signer_peer::receive(socket.as_raw_fd(), RESPONSE_MAX_BYTES + LENGTH_BYTES)
                    .map_err(|_| Refusal::Transport)?;
            // Every packet needs the captured signer identity; passing a socket cannot transfer its authority.
            if !peer.matches(&packet) {
                return Err(Refusal::Peer);
            }
            if !packet.rights.is_empty() {
                return Err(Refusal::Rights);
            }
            return Ok(packet.bytes);
        }
    }
    fn exchange(&mut self, bytes: &[u8], end: u64) -> Result<Value> {
        if self.outstanding {
            return self.fail(Refusal::Busy);
        }
        let result = (|| {
            let socket = self.socket.as_ref().ok_or(Refusal::State)?;
            if signer_service::readable(socket.as_raw_fd()) {
                return Err(Refusal::Unmatched);
            }
            self.outstanding = true;
            self.settlement_end =
                Some(Instant::now() + Duration::from_millis(SIGNER_REQUEST_DEADLINE_MS as u64));
            signer_peer::send(socket.as_raw_fd(), bytes, &[]).map_err(|_| Refusal::Transport)?;
            let packet = Self::receive(
                socket,
                self.peer.as_ref().ok_or(Refusal::State)?,
                &self.clock,
                end,
                Instant::now() + Duration::from_nanos(end.saturating_sub(self.now()?)),
            )?;
            self.settlement_end = None;
            let value = packet_value(&packet)?;
            if signer_service::readable(socket.as_raw_fd()) {
                return Err(Refusal::DuplicateReply);
            }
            if value["op"] == "REFUSED" {
                return Err(Refusal::Refused);
            }
            Ok(value)
        })();
        match result {
            Ok(value) => {
                self.outstanding = false;
                Ok(value)
            }
            Err(error) => self.fail(error),
        }
    }
    pub fn status(&mut self) -> Result<StatusReply> {
        let result = self.status_inner();
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }
    fn status_inner(&mut self) -> Result<StatusReply> {
        if !matches!(
            self.state,
            SignerClientState::Unbound | SignerClientState::Bound
        ) {
            return self.fail(Refusal::State);
        }
        let now = self.now()?;
        let mut end = now
            .checked_add(SIGNER_REQUEST_DEADLINE_MS as u64 * NS_PER_MS)
            .ok_or(Refusal::Deadline)?;
        if let Some(frozen) = &self.frozen {
            if !Self::live(frozen, now) {
                return self.fail(Refusal::Expired);
            }
            end = end.min(
                frozen
                    .expires_boottime_ns
                    .parse()
                    .map_err(|_| Refusal::Schema)?,
            );
        }
        let value = self.exchange(b"{\"op\":\"STATUS\"}", end)?;
        let view = match parse_status_value(value) {
            Ok(view) => view,
            Err(error) => return self.fail(error),
        };
        if let Some(frozen) = &self.frozen {
            if !Self::unchanged(frozen, &view) || view.state != "UNLOCKED" {
                return self.fail(Refusal::Grant);
            }
            if !Self::live(frozen, self.now()?) {
                return self.fail(Refusal::Expired);
            }
        }
        if self.now()? >= end {
            return self.fail(Refusal::Deadline);
        }
        self.latest = view.clone();
        Ok(view)
    }
    pub fn sign_record(&mut self, header: Header, preimage: &[u8]) -> Result<SignedReply> {
        let result = self.sign_record_inner(header, preimage);
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }
    fn sign_record_inner(&mut self, header: Header, preimage: &[u8]) -> Result<SignedReply> {
        if self.state != SignerClientState::Bound {
            return self.fail(Refusal::State);
        }
        if self.outstanding {
            return self.fail(Refusal::Busy);
        }
        let now = self.now()?;
        let frozen = self.frozen.clone().ok_or(Refusal::State)?;
        if !Self::live(&frozen, now) {
            return self.fail(Refusal::Expired);
        }
        let grant = &frozen.grant;
        if header.role != grant.role
            || header.epoch != grant.epoch
            || header.activation_id != grant.activation_id
            || header.lease_id != grant.lease_id
            || header.generation != grant.generation
        {
            return self.fail(Refusal::Grant);
        }
        if header.preimage_length != preimage.len() || preimage.len() > SIGNER_PREIMAGE_MAX_BYTES {
            return self.fail(Refusal::Preimage);
        }
        let limit = now
            .checked_add(SIGNER_REQUEST_DEADLINE_MS as u64 * NS_PER_MS)
            .ok_or(Refusal::Deadline)?;
        let deadline = match header.deadline_boottime_ns.parse::<u64>() {
            Ok(n) if n.to_string() == header.deadline_boottime_ns && n > now && n <= limit => n,
            _ => return self.fail(Refusal::Deadline),
        };
        if header.v != 1
            || header.protocol != SIGNER_PROTOCOL
            || !hex_text(&json!(header.request_id), "", ID_HEX_CHARS)
        {
            return self.fail(Refusal::Header);
        }
        let wire = json!({"v":header.v,"protocol":header.protocol,"request_id":header.request_id,"activation_id":header.activation_id,"lease_id":header.lease_id,"generation":header.generation,"epoch":header.epoch,"role":header.role,"deadline_boottime_ns":header.deadline_boottime_ns,"preimage_length":header.preimage_length});
        let bytes = signer_service::encode(&wire, preimage).map_err(|_| Refusal::Header)?;
        // A request deadline is fixed when the request is admitted; no reply, heartbeat or status can extend it.
        let end = deadline.min(limit).min(
            frozen
                .expires_boottime_ns
                .parse()
                .map_err(|_| Refusal::Schema)?,
        );
        let value = self.exchange(&bytes, end)?;
        if value["op"] != "SIGNED" {
            return self.fail(Refusal::Unmatched);
        }
        let expected = ["kid", "op", "request_id", "signature"];
        if !value.as_object().is_some_and(|map| {
            map.len() == expected.len() && expected.iter().all(|key| map.contains_key(*key))
        }) {
            return self.fail(Refusal::Schema);
        }
        if value["request_id"].as_str() != Some(header.request_id.as_str()) {
            return self.fail(Refusal::Unmatched);
        }
        if value["kid"].as_str() != Some(grant.kid.as_str()) {
            return self.fail(Refusal::Grant);
        }
        let signature = match value["signature"]
            .as_str()
            .and_then(|text| {
                URL_SAFE_NO_PAD
                    .decode(text)
                    .ok()
                    .filter(|bytes| URL_SAFE_NO_PAD.encode(bytes) == text)
            })
            .and_then(|bytes| <[u8; SIGNATURE_BYTES]>::try_from(bytes).ok())
        {
            Some(bytes) => bytes,
            None => return self.fail(Refusal::Schema),
        };
        // A signature carries authority only for the admitted bytes under the frozen role domain and key.
        if !signer_service::verify_worker_signature(
            &value,
            &serde_json::to_value(grant).map_err(|_| Refusal::Schema)?,
            preimage,
        ) {
            return self.fail(Refusal::Signature);
        }
        if self.now()? >= end {
            return self.fail(Refusal::Deadline);
        }
        Ok(SignedReply {
            request_id: header.request_id,
            kid: grant.kid.clone(),
            signature,
        })
    }
    fn settle_io(&mut self) {
        if let (Some(end), Some(socket), Some(peer)) = (
            self.settlement_end.take(),
            self.socket.as_ref(),
            self.peer.as_ref(),
        ) {
            // The original settlement deadline never restarts, and a late reply is discarded while the slot remains owned.
            while Instant::now() < end && peer.live() {
                let timeout = end
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(i32::MAX as u128) as i32;
                let mut poll = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, timeout) } < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if poll.revents != 0 {
                    let _ =
                        signer_peer::receive(socket.as_raw_fd(), RESPONSE_MAX_BYTES + LENGTH_BYTES);
                    break;
                }
            }
        }
    }
    pub fn close_and_settle(&mut self) {
        // The slot is released only after retained I/O has settled or the fixed deadline has passed.
        self.state = SignerClientState::Settling;
        self.settle_io();
        self.socket.take();
        self.peer.take();
        self.outstanding = false;
        self.state = SignerClientState::Closed;
    }
}
impl Drop for BusinessSignerClient {
    fn drop(&mut self) {
        self.close_and_settle();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::os::fd::FromRawFd;
    #[test]
    fn retained_slot_refuses_another_sign_before_any_send() {
        // Exclusive mutable access makes this state internal; the guard still refuses retained work before transport effects.
        let mut fds = [-1; 2]; // The two ends of one scripted peer connection.
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let socket = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let other = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        signer_peer::passcred(socket.as_raw_fd()).unwrap();
        let policy = PeerPolicy {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            executable_sha256: hex::encode(Sha256::digest(
                std::fs::read("/proc/self/exe").unwrap(),
            )),
            cgroup: std::fs::read_to_string("/proc/self/cgroup")
                .unwrap()
                .trim()
                .into(),
        };
        let peer = Peer::capture(socket.as_raw_fd(), &policy).unwrap();
        let corpus: Value =
            serde_json::from_str(include_str!("signer_status_vectors.json")).unwrap();
        let view = parse_status_packet(
            &hex::decode(corpus["cases"][0]["packet_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let grant = &view.grant;
        let roles: Value = serde_json::from_str(include_str!("role_vectors.json")).unwrap();
        let preimage = hex::decode(roles[0]["preimage"].as_str().unwrap()).unwrap();
        let header = Header {
            v: 1,
            protocol: SIGNER_PROTOCOL.into(),
            request_id: "d".repeat(ID_HEX_CHARS),
            role: grant.role.clone(),
            epoch: grant.epoch,
            activation_id: grant.activation_id.clone(),
            lease_id: grant.lease_id.clone(),
            generation: grant.generation,
            deadline_boottime_ns: (SIGNER_REQUEST_DEADLINE_MS as u64 * NS_PER_MS).to_string(),
            preimage_length: preimage.len(),
        };
        let mut client = BusinessSignerClient {
            socket: Some(socket),
            peer: Some(peer),
            state: SignerClientState::Bound,
            latest: view.clone(),
            frozen: Some(view),
            outstanding: true,
            settlement_end: None,
            clock: Arc::new(|| Ok(1)),
        };
        assert_eq!(client.sign_record(header, &preimage), Err(Refusal::Busy));
        let mut byte = 0u8;
        assert_eq!(
            unsafe {
                libc::recv(
                    other.as_raw_fd(),
                    &mut byte as *mut _ as _,
                    1,
                    libc::MSG_DONTWAIT,
                )
            },
            0
        );
        assert_eq!(client.state(), SignerClientState::Settling);
        client.close_and_settle();
        assert_eq!(client.state(), SignerClientState::Closed);
    }
}
