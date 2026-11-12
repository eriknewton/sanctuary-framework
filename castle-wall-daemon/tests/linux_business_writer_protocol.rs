// fail-before-exempt: the writer wire entrypoint is new.
#![cfg(target_os = "linux")]
mod isolation;
use castle_wall_daemon::business_profile::{
    signer_contract::*, signer_service, writer_protocol::*,
};
use serde_json::{json, Value};
const SESSION: &str = "11111111111111111111111111111111";
const REQUEST: &str = "22222222222222222222222222222222";
fn header(size: usize) -> signer_service::Header {
    signer_service::Header {
        v: 1,
        protocol: SIGNER_PROTOCOL.into(),
        request_id: REQUEST.into(),
        activation_id: SESSION.into(),
        lease_id: REQUEST.into(),
        generation: 1,
        epoch: 1,
        role: ROLE_REGISTRY[0].0.into(),
        deadline_boottime_ns: "1000000000".into(),
        preimage_length: size,
    }
}
fn raw(value: &Value, body: &[u8]) -> Vec<u8> {
    signer_service::encode(value, body).unwrap()
}
fn hello() -> Value {
    json!({"v":1,"protocol":WRITER_PROTOCOL,"op":"HELLO","session_id":SESSION})
}
fn bad_header(mutator: impl FnOnce(&mut Value), expected: Refusal) {
    let mut value = hello();
    mutator(&mut value);
    assert_eq!(
        decode(&raw(&value, &[]), Direction::ToWall, SESSION).unwrap_err(),
        expected
    );
}
// The wall stand-in must match writer_protocol: it imports the same encoder and decoder.
#[test]
fn hello_then_ack_then_status_is_the_only_handshake() {
    let mut handshake = Handshake::new(SESSION.into()).unwrap();
    assert!(matches!(
        decode(&handshake.hello().unwrap(), Direction::ToWall, SESSION)
            .unwrap()
            .operation,
        Operation::Hello
    ));
    let ack = encode(Direction::ToWriter, SESSION, &Operation::HelloAck, &[]).unwrap();
    handshake.receive(&ack).unwrap();
    assert_eq!(handshake.state(), HandshakeState::Established);
    let status = encode(
        Direction::ToWriter,
        SESSION,
        &Operation::Status {
            request_id: REQUEST.into(),
        },
        &[],
    )
    .unwrap();
    handshake.receive(&status).unwrap();
    assert_eq!(handshake.receive(&ack).unwrap_err(), Refusal::Handshake);
    assert_eq!(handshake.state(), HandshakeState::Closed);
}
#[test]
fn early_requests_close_the_handshake() {
    for op in [
        Operation::Status {
            request_id: REQUEST.into(),
        },
        Operation::Sign(header(0)),
    ] {
        let mut handshake = Handshake::new(SESSION.into()).unwrap();
        let packet = encode(Direction::ToWriter, SESSION, &op, &[]).unwrap();
        assert_eq!(handshake.receive(&packet).unwrap_err(), Refusal::Handshake);
        assert_eq!(handshake.state(), HandshakeState::Closed);
    }
}
#[test]
fn session_mismatch_refuses_ack_and_later_packet() {
    for op in [
        Operation::HelloAck,
        Operation::Status {
            request_id: REQUEST.into(),
        },
    ] {
        let packet = encode(Direction::ToWriter, REQUEST, &op, &[]).unwrap();
        assert_eq!(
            decode(&packet, Direction::ToWriter, SESSION).unwrap_err(),
            Refusal::Session
        );
    }
}
#[test]
fn trailing_bytes_are_never_another_record() {
    let mut packet = raw(&hello(), &[]);
    packet.push(0);
    assert_eq!(
        decode(&packet, Direction::ToWall, SESSION).unwrap_err(),
        Refusal::Length
    );
}
#[test]
fn missing_unknown_duplicate_and_noncanonical_headers_refuse() {
    bad_header(
        |v| {
            v.as_object_mut().unwrap().remove("v");
        },
        Refusal::Schema,
    );
    bad_header(|v| v["unknown"] = json!(true), Refusal::Schema);
    let canonical = raw(&hello(), &[]);
    let text = std::str::from_utf8(&canonical[LENGTH_BYTES..]).unwrap();
    for changed in [format!("{{\"v\":1,{}", &text[1..]), format!(" {text}")] {
        let packet = [
            (changed.len() as u32).to_be_bytes().as_slice(),
            changed.as_bytes(),
        ]
        .concat();
        assert_eq!(
            decode(&packet, Direction::ToWall, SESSION).unwrap_err(),
            Refusal::Canonical
        );
    }
}
#[test]
fn version_protocol_operation_and_direction_are_strict() {
    bad_header(|v| v["v"] = json!(2), Refusal::Schema);
    bad_header(|v| v["protocol"] = json!(SIGNER_PROTOCOL), Refusal::Schema);
    bad_header(|v| v["op"] = json!("UNKNOWN"), Refusal::Schema);
    assert_eq!(
        decode(&raw(&hello(), &[]), Direction::ToWriter, SESSION).unwrap_err(),
        Refusal::Direction
    );
}
#[test]
fn header_and_directional_bounds_precede_json() {
    for direction in [Direction::ToWriter, Direction::ToWall] {
        assert_eq!(
            decode(&vec![0; direction.cap() + 1], direction, SESSION).unwrap_err(),
            Refusal::Length
        );
    }
    for length in [0, LENGTH_BYTES - 1] {
        assert_eq!(
            decode(&vec![0; length], Direction::ToWriter, SESSION).unwrap_err(),
            Refusal::Length
        );
    }
    for length in [WRITER_HEADER_MAX_BYTES + 1, u32::MAX as usize] {
        assert_eq!(
            decode(&(length as u32).to_be_bytes(), Direction::ToWriter, SESSION).unwrap_err(),
            Refusal::Length
        );
    }
}
#[test]
fn sign_uses_preimage_bound_and_reply_uses_envelope_bound() {
    for size in [WRITER_REPLY_PACKET_MAX_BYTES + 1, SIGNER_PREIMAGE_MAX_BYTES] {
        let body = vec![b'x'; size];
        let packet = encode(
            Direction::ToWriter,
            SESSION,
            &Operation::Sign(header(size)),
            &body,
        )
        .unwrap();
        assert_eq!(
            decode(&packet, Direction::ToWriter, SESSION)
                .unwrap()
                .payload,
            body
        );
    }
    assert!(encode(
        Direction::ToWriter,
        SESSION,
        &Operation::Sign(header(SIGNER_PREIMAGE_MAX_BYTES + 1)),
        &vec![0; SIGNER_PREIMAGE_MAX_BYTES + 1]
    )
    .is_err());
    for (op, field, cap) in [
        ("VERIFIED", "envelope_length", WRITER_ENVELOPE_MAX_BYTES),
        ("STATUS", "status_length", WRITER_STATUS_MAX_BYTES),
    ] {
        for size in [cap, cap + 1] {
            let mut value = hello();
            value["op"] = json!(op);
            value["request_id"] = json!(REQUEST);
            value[field] = json!(size);
            let packet = raw(&value, &vec![0; size]);
            assert_eq!(
                decode(&packet, Direction::ToWall, SESSION).unwrap_err(),
                if size == cap {
                    Refusal::Canonical
                } else {
                    Refusal::Length
                }
            );
        }
    }
}
#[test]
fn declared_payload_length_must_equal_packet() {
    let packet = encode(
        Direction::ToWriter,
        SESSION,
        &Operation::Sign(header(1)),
        &[0],
    )
    .unwrap();
    for changed in [
        packet[..packet.len() - 1].to_vec(),
        [packet, vec![0]].concat(),
    ] {
        assert!(decode(&changed, Direction::ToWriter, SESSION).is_err());
    }
    for op in [
        Operation::Hello,
        Operation::Refused {
            request_id: REQUEST.into(),
        },
    ] {
        assert_eq!(
            encode(Direction::ToWall, SESSION, &op, &[0]).unwrap_err(),
            Refusal::Length
        );
    }
}
#[test]
fn sign_fields_share_the_native_signer_schema() {
    let packet = encode(
        Direction::ToWriter,
        SESSION,
        &Operation::Sign(header(0)),
        &[],
    )
    .unwrap();
    let source: Value = serde_json::from_slice(&packet[LENGTH_BYTES..]).unwrap();
    for (field, bad) in [
        ("request_id", json!("x")),
        ("activation_id", json!("x")),
        ("lease_id", json!("x")),
        ("epoch", json!(0)),
        ("generation", json!(-1)),
        ("role", json!("unknown")),
        ("deadline_boottime_ns", json!("01")),
        ("preimage_length", json!(1)),
    ] {
        let mut value = source.clone();
        value[field] = bad;
        assert!(
            decode(&raw(&value, &[]), Direction::ToWriter, SESSION).is_err(),
            "{field}"
        );
    }
    // The writer retains an unparseable string for writer_service's correlated admission reply.
    for deadline in ["invalid", "", "18446744073709551616"] {
        let mut value = source.clone();
        value["deadline_boottime_ns"] = json!(deadline);
        let packet = raw(&value, &[]);
        let frame = decode(&packet, Direction::ToWriter, SESSION).unwrap();
        let Operation::Sign(header) = frame.operation else {
            panic!("SIGN header retained")
        };
        assert_eq!(header.deadline_boottime_ns, deadline);
    }
}
fn first_record() -> Value {
    let corpus: Value = serde_json::from_str(include_str!(
        "../src/business_profile/record_join_vectors.json"
    ))
    .unwrap();
    fn find(value: &Value) -> Option<Value> {
        if value.get("body").is_some() && value.get("outer").is_some() {
            return Some(value.clone());
        }
        match value {
            Value::Array(a) => a.iter().find_map(find),
            Value::Object(m) => m.values().find_map(find),
            _ => None,
        }
    }
    find(&corpus).unwrap()
}
fn canonical(value: &Value) -> Vec<u8> {
    // serde's sorted string-key object is canonical for these integer-only fixtures.
    serde_json::to_vec(value).unwrap()
}
#[test]
fn envelope_preserves_body_and_the_complete_outer_index() {
    let record = first_record();
    let body = canonical(&record["body"]);
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let sig: [u8; SIGNATURE_BYTES] = URL_SAFE_NO_PAD
        .decode(record["outer"]["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        record["outer"]["signature"].as_str().unwrap().len(),
        SIGNATURE_TEXT_BYTES
    );
    let bytes = envelope(&body, &sig).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value, record);
    assert_eq!(canonical(&value["body"]), body);
    assert_eq!(measured_envelope(&body).unwrap(), bytes.len());
    assert!(bytes.len() <= WRITER_ENVELOPE_MAX_BYTES);
    assert_eq!(
        measured_envelope(&[b" ".as_slice(), &body].concat()).unwrap_err(),
        Refusal::Canonical
    );
}
#[test]
fn status_has_seven_keys_and_a_shared_typed_grant() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../src/business_profile/signer_status_vectors.json"
    ))
    .unwrap();
    let packet = hex::decode(corpus["cases"][0]["packet_hex"].as_str().unwrap()).unwrap();
    let parsed =
        castle_wall_daemon::business_profile::signer_client::parse_status_packet(&packet).unwrap();
    for granted in [false, true] {
        let payload = StatusPayload::from_signer(&parsed, granted);
        let bytes = payload.encode().unwrap();
        assert_eq!(StatusPayload::decode(&bytes).unwrap(), payload);
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 7);
        assert_eq!(value["grant"].is_null(), !granted);
        let mut bad = value.clone();
        bad["extra"] = json!(0);
        assert_eq!(
            StatusPayload::decode(&canonical(&bad)).unwrap_err(),
            Refusal::Schema
        );
    }
}

#[test]
fn transport_refuses_rights_and_truncation() {
    use castle_wall_daemon::business_profile::signer_peer;
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
    use std::os::fd::AsRawFd;
    for (rights, size, accepted) in [
        (false, 1, true),
        (true, 1, false),
        (false, WRITER_SIGN_PACKET_MAX_BYTES + 1, false),
    ] {
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        signer_peer::passcred(b.as_raw_fd()).unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let fds = if rights {
            vec![file.as_raw_fd()]
        } else {
            vec![]
        };
        if size > WRITER_SIGN_PACKET_MAX_BYTES {
            let bytes = vec![0u8; size];
            assert_eq!(
                unsafe {
                    libc::send(
                        a.as_raw_fd(),
                        bytes.as_ptr() as _,
                        bytes.len(),
                        libc::MSG_NOSIGNAL,
                    )
                },
                size as isize
            );
        } else {
            signer_peer::send(a.as_raw_fd(), &vec![0; size], &fds).unwrap();
        }
        assert_eq!(
            receive(b.as_raw_fd(), Direction::ToWriter).is_ok(),
            accepted
        );
    }
}

#[path = "support/writer_state.rs"]
mod writer_state;
#[test]
fn signature_for_another_valid_body_cannot_make_a_verified_envelope() {
    use castle_wall_daemon::business_profile::writer_service::Error;
    use std::sync::atomic::Ordering;
    let f = writer_state::Fixture::new();
    let mut machine = f.machine();
    f.grant(&mut machine);
    let envelope = machine.sign(f.header(), &f.body, |_| Ok(())).unwrap();
    assert_eq!(
        decode_envelope(&envelope).unwrap()["body"],
        serde_json::from_slice::<Value>(&f.body).unwrap()
    );
    machine.verified_sent_for_test();
    let corpus: Value = serde_json::from_str(include_str!(
        "../src/business_profile/record_join_vectors.json"
    ))
    .unwrap();
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    *f.signature.lock().unwrap() = URL_SAFE_NO_PAD
        .decode(
            corpus["cases"][2]["records"][1]["outer"]["signature"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        machine.sign(f.header(), &f.body, |_| Ok(())),
        Err(Error::Signature)
    );
    assert_eq!(f.signs.load(Ordering::SeqCst), 2);
}
#[test]
fn noncanonical_body_never_reaches_the_signer() {
    use std::sync::atomic::Ordering;
    let f = writer_state::Fixture::new();
    let mut machine = f.machine();
    f.grant(&mut machine);
    let body = [b" ".as_slice(), &f.body].concat();
    let mut h = f.header();
    h.preimage_length = body.len();
    assert!(machine.sign(h, &body, |_| Ok(())).is_err());
    assert_eq!(f.signs.load(Ordering::SeqCst), 0);
}

#[test]
fn encoded_envelope_size_has_an_exact_defensive_bound() {
    assert!(envelope_size_admitted_for_test(WRITER_ENVELOPE_MAX_BYTES));
    assert!(!envelope_size_admitted_for_test(
        WRITER_ENVELOPE_MAX_BYTES + 1
    ));
}
