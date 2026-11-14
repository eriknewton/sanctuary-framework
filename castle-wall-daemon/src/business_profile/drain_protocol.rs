//! Drain wire authority is request-derived; replies never confer a writer lease by themselves.
use super::{
    activation_anchor as anchor,
    drain_store::{self, Phase},
    frame, writer_protocol,
};
pub use drain_store::{
    DRAIN_SLOTS, D_ANCHOR_MESSAGE_MAX_BYTES, D_ANCHOR_PAYLOAD_MAX_BYTES, D_CLASSIFY_DEADLINE_MS,
    D_CONNECTIONS_MAX, D_HEADER_MAX_BYTES, D_HEARTBEAT_MS, D_LEASE_MS, D_REPLY_MAX_BYTES,
    D_REQUEST_DEADLINE_MS, D_REQUEST_MAX_BYTES,
};
use serde_json::{json, Value};
pub const D_PROTOCOL: &str = "sanctuary.business-drain.v1";
// Must match the future drain unit's RuntimeDirectory and its listener consumer in drain_service.
pub const DRAIN_SOCKET: &str = "/run/sanctuary-business-drain/drain.sock";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Length,
    Canonical,
    Schema,
    Direction,
    Role,
    Message,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToDrain,
    FromDrain,
}
#[derive(Debug)]
pub enum Operation<'a> {
    Read,
    Anchor {
        message: Value,
        envelope: &'a [u8],
    },
    Original {
        sequence: u64,
        envelope: &'a [u8],
    },
    ReadReply {
        anchor: Option<Value>,
        latched: bool,
        uncertain: bool,
    },
    AnchorAck {
        anchor: Value,
    },
    OriginalAck {
        sequence: u64,
        drained_digest: String,
    },
    Refused,
}
#[derive(Debug)]
pub struct Frame<'a> {
    pub request_id: String,
    pub role: String,
    pub operation: Operation<'a>,
}
pub fn canonical(bytes: &[u8], cap: usize) -> Result<Value, Refusal> {
    frame::canonical(bytes, cap).map_err(|_| Refusal::Canonical)
}
fn hex_text(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn id(s: &str) -> bool {
    hex_text(s, anchor::ID_HEX_LENGTH)
}
pub fn digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|s| hex_text(s, anchor::DIGEST_HEX_LENGTH))
}
fn exact(h: &Value, extras: &[&str]) -> Result<(), Refusal> {
    const COMMON: &[&str] = &["v", "protocol", "op", "request_id", "role"];
    if !h.as_object().is_some_and(|o| {
        o.len() == COMMON.len() + extras.len()
            && COMMON.iter().chain(extras).all(|k| o.contains_key(*k))
    }) {
        return Err(Refusal::Schema);
    }
    Ok(())
}
fn length(h: &Value, name: &str, cap: usize) -> Result<usize, Refusal> {
    h[name]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n <= cap)
        .ok_or(Refusal::Length)
}
fn sequence(h: &Value) -> Result<u64, Refusal> {
    h["sequence"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= anchor::SAFE_INTEGER) // Sequence shares the anchor exact-JSON-integer domain.
        .ok_or(Refusal::Schema)
}
pub fn decode(packet: &[u8], direction: Direction) -> Result<Frame<'_>, Refusal> {
    let cap = match direction {
        Direction::ToDrain => D_REQUEST_MAX_BYTES,
        Direction::FromDrain => D_REPLY_MAX_BYTES,
    };
    let (h, p) = frame::split(packet, D_HEADER_MAX_BYTES, cap).map_err(|e| match e {
        frame::Refusal::Length => Refusal::Length,
        frame::Refusal::Canonical => Refusal::Canonical,
    })?;
    let request_id = h["request_id"]
        .as_str()
        .filter(|s| id(s))
        .ok_or(Refusal::Schema)?
        .to_owned();
    let role = h["role"].as_str().ok_or(Refusal::Role)?.to_owned();
    // Only the fixed producer table maps wire roles to storage; unknown and retrospective roles acquire no mutation authority.
    if !DRAIN_SLOTS.iter().any(|(_, wire)| *wire == role) {
        return Err(Refusal::Role);
    }
    if h["v"] != 1 || h["protocol"] != D_PROTOCOL {
        return Err(Refusal::Schema);
    }
    let op = h["op"].as_str().ok_or(Refusal::Schema)?;
    let operation = match (direction, op) {
        (Direction::ToDrain, "READ") => {
            exact(&h, &[])?;
            if !p.is_empty() {
                return Err(Refusal::Length);
            }
            Operation::Read
        }
        (Direction::ToDrain, "ANCHOR") => {
            exact(&h, &["message_length", "envelope_length"])?;
            let m = length(&h, "message_length", D_ANCHOR_MESSAGE_MAX_BYTES)?;
            let e = length(
                &h,
                "envelope_length",
                writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
            )?;
            if m.checked_add(e) != Some(p.len()) {
                return Err(Refusal::Length);
            }
            let message = anchor::decode_message(&p[..m]).ok_or(Refusal::Message)?;
            if message["request_id"] != request_id
                || matches!(message["op"].as_str(), Some("DRAIN" | "READ"))
            {
                return Err(Refusal::Message);
            }
            if (Phase::of_message(&message) == Some(Phase::RECORD_COMMIT)) != (e > 0) {
                return Err(Refusal::Message);
            }
            Operation::Anchor {
                message,
                envelope: &p[m..],
            }
        }
        (Direction::ToDrain, "ORIGINAL") => {
            exact(&h, &["sequence", "payload_length"])?;
            if length(
                &h,
                "payload_length",
                writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
            )? != p.len()
            {
                return Err(Refusal::Length);
            }
            Operation::Original {
                sequence: sequence(&h)?,
                envelope: p,
            }
        }
        (Direction::FromDrain, "READ_REPLY" | "ANCHOR_ACK") => {
            if op == "READ_REPLY" {
                exact(
                    &h,
                    &[
                        "state",
                        "latched",
                        "uncertain",
                        "anchor_digest",
                        "payload_length",
                    ],
                )?;
            } else {
                exact(&h, &["anchor_digest", "payload_length"])?;
            }
            if length(&h, "payload_length", anchor::MAX_BYTES)? != p.len() {
                return Err(Refusal::Length);
            }
            let value = if p.is_empty() {
                None
            } else {
                let a = canonical(p, anchor::MAX_BYTES)?;
                if !anchor::valid(&a)
                    || a["role"] != role
                    || anchor::anchor_digest(&a).as_deref() != h["anchor_digest"].as_str()
                {
                    return Err(Refusal::Schema);
                }
                Some(a)
            };
            if op == "ANCHOR_ACK" {
                Operation::AnchorAck {
                    anchor: value.ok_or(Refusal::Schema)?,
                }
            } else {
                let latched = h["latched"].as_bool().ok_or(Refusal::Schema)?;
                let uncertain = h["uncertain"].as_bool().ok_or(Refusal::Schema)?;
                if h["state"] != if value.is_some() { "PRESENT" } else { "ABSENT" }
                    || latched
                        != value
                            .as_ref()
                            .is_some_and(|a| a["recovery_required"] == true)
                    || (value.is_none() && !h["anchor_digest"].is_null())
                {
                    return Err(Refusal::Schema);
                }
                Operation::ReadReply {
                    anchor: value,
                    latched,
                    uncertain,
                }
            }
        }
        (Direction::FromDrain, "ORIGINAL_ACK") => {
            exact(&h, &["sequence", "drained_digest"])?;
            if !p.is_empty() {
                return Err(Refusal::Length);
            }
            Operation::OriginalAck {
                sequence: sequence(&h)?,
                drained_digest: h["drained_digest"]
                    .as_str()
                    .filter(|s| digest(s))
                    .ok_or(Refusal::Schema)?
                    .to_owned(),
            }
        }
        (Direction::FromDrain, "REFUSED") => {
            exact(&h, &[])?;
            if !p.is_empty() {
                return Err(Refusal::Length);
            }
            Operation::Refused
        }
        _ => return Err(Refusal::Direction),
    };
    Ok(Frame {
        request_id,
        role,
        operation,
    })
}
/// Encoders use the receiving decoder, so the two directions have one schema.
pub fn encode(header: &Value, payload: &[u8], direction: Direction) -> Result<Vec<u8>, Refusal> {
    let bytes = crate::smb::jcs::encode(header).map_err(|_| Refusal::Canonical)?;
    let cap = match direction {
        Direction::ToDrain => D_REQUEST_MAX_BYTES,
        Direction::FromDrain => D_REPLY_MAX_BYTES,
    };
    if bytes.len() > D_HEADER_MAX_BYTES || payload.len() > cap {
        return Err(Refusal::Length);
    }
    let packet = [
        &(bytes.len() as u32).to_be_bytes()[..],
        bytes.as_bytes(),
        payload,
    ]
    .concat();
    decode(&packet, direction)?;
    Ok(packet)
}
pub fn header(op: &str, request_id: &str, role: &str) -> Value {
    json!({"v":1,"protocol":D_PROTOCOL,"op":op,"request_id":request_id,"role":role})
}

#[cfg(test)]
mod tests {
    // fail-before-exempt: New drain codec component; service witnesses exercise the same decoder.
    use super::*;
    fn raw(h: &Value, p: &[u8]) -> Vec<u8> {
        let b = crate::smb::jcs::encode(h).unwrap();
        [&(b.len() as u32).to_be_bytes()[..], b.as_bytes(), p].concat()
    }
    #[test]
    fn strict_read_frames_and_direction() {
        let h = header("READ", &"a".repeat(anchor::ID_HEX_LENGTH), DRAIN_SLOTS[0].1);
        let p = raw(&h, &[]);
        assert!(matches!(
            decode(&p, Direction::ToDrain).unwrap().operation,
            Operation::Read
        ));
        assert_eq!(
            decode(&p, Direction::FromDrain).unwrap_err(),
            Refusal::Direction
        );
        let mut extra = h.clone();
        extra["extra"] = json!(true);
        assert_eq!(
            decode(&raw(&extra, &[]), Direction::ToDrain).unwrap_err(),
            Refusal::Schema
        );
        for role in ["unknown", "linux-business-retrospective"] {
            let mut v = h.clone();
            v["role"] = json!(role);
            assert_eq!(
                decode(&raw(&v, &[]), Direction::ToDrain).unwrap_err(),
                Refusal::Role
            );
        }
        assert_eq!(
            decode(&raw(&h, b"x"), Direction::ToDrain).unwrap_err(),
            Refusal::Length
        );
        for n in 0..frame::LENGTH_BYTES {
            assert_eq!(
                decode(&p[..n], Direction::ToDrain).unwrap_err(),
                Refusal::Length
            );
        }
        let mut oversized = p.clone();
        oversized[..frame::LENGTH_BYTES].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode(&oversized, Direction::ToDrain).unwrap_err(),
            Refusal::Length
        );
    }
    #[test]
    fn observational_absence_and_noncanonical_headers() {
        let mut h = header(
            "READ_REPLY",
            &"b".repeat(anchor::ID_HEX_LENGTH),
            DRAIN_SLOTS[0].1,
        );
        h["state"] = json!("ABSENT");
        h["latched"] = json!(false);
        h["uncertain"] = json!(true);
        h["anchor_digest"] = Value::Null;
        h["payload_length"] = json!(0);
        assert!(matches!(
            decode(&raw(&h, &[]), Direction::FromDrain)
                .unwrap()
                .operation,
            Operation::ReadReply {
                anchor: None,
                latched: false,
                uncertain: true
            }
        ));
        let text = serde_json::to_string_pretty(&h).unwrap();
        let p = [&(text.len() as u32).to_be_bytes()[..], text.as_bytes()].concat();
        assert_eq!(
            decode(&p, Direction::FromDrain).unwrap_err(),
            Refusal::Canonical
        );
        h["latched"] = json!(true);
        assert_eq!(
            decode(&raw(&h, &[]), Direction::FromDrain).unwrap_err(),
            Refusal::Schema
        );
    }
    #[test]
    fn anchor_bounds_precede_message_decode() {
        let mut h = header(
            "ANCHOR",
            &"c".repeat(anchor::ID_HEX_LENGTH),
            DRAIN_SLOTS[0].1,
        );
        h["message_length"] = json!(D_ANCHOR_MESSAGE_MAX_BYTES + 1);
        h["envelope_length"] = json!(0);
        assert_eq!(
            decode(
                &raw(&h, &vec![b' '; D_ANCHOR_MESSAGE_MAX_BYTES + 1]),
                Direction::ToDrain
            )
            .unwrap_err(),
            Refusal::Length
        );
        h["message_length"] = json!(0);
        h["envelope_length"] = json!(writer_protocol::WRITER_ENVELOPE_MAX_BYTES + 1);
        assert_eq!(
            decode(&raw(&h, &[]), Direction::ToDrain).unwrap_err(),
            Refusal::Length
        );
    }
}
