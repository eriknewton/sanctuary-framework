//! Integration tests covering the IPC framing + envelope shapes end-to-end.
//!
//! PR 2a integration coverage focuses on the contract path: a TS-side mock
//! produces frames using the same constants this crate exposes; this test
//! exercises round-trip parsing and envelope deserialization to catch any
//! drift between the TS and Rust implementations early.

use castle_wall_daemon::ipc::framing::{frame, parse_frame, ParseStep};
use castle_wall_daemon::ipc::messages::{IpcMessage, MessageEnvelope};

#[test]
fn handshake_envelope_round_trip() {
    let envelope = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: "castle-wall.handshake_challenge".to_string(),
        params: IpcMessage::HandshakeChallenge {
            nonce_b64url: "deadbeef".to_string(),
            protocol_version: None,
            capabilities: Vec::new(),
        },
    };
    let json = serde_json::to_string(&envelope).expect("serialize");
    let framed = frame(&json);
    let parsed_body = match parse_frame(&framed) {
        ParseStep::Complete {
            body,
            consumed_bytes,
        } => {
            assert_eq!(consumed_bytes, framed.len());
            body
        }
        other => panic!("expected Complete, got {:?}", other),
    };
    let back: MessageEnvelope = serde_json::from_str(&parsed_body).expect("deserialize");
    assert_eq!(back, envelope);
}

#[test]
fn back_to_back_frames_split_correctly() {
    let first = frame("{\"a\":1}");
    let second = frame("{\"b\":2}");
    let mut buf = Vec::new();
    buf.extend_from_slice(&first);
    buf.extend_from_slice(&second);

    let consumed = match parse_frame(&buf) {
        ParseStep::Complete {
            body,
            consumed_bytes,
        } => {
            assert_eq!(body, "{\"a\":1}");
            consumed_bytes
        }
        other => panic!("expected first Complete, got {:?}", other),
    };
    let remainder = &buf[consumed..];
    match parse_frame(remainder) {
        ParseStep::Complete { body, .. } => assert_eq!(body, "{\"b\":2}"),
        other => panic!("expected second Complete, got {:?}", other),
    }
}

#[test]
fn unknown_message_type_fails_deserialization() {
    let body = "{\"type\":\"unknown_message\",\"x\":1}";
    let parsed: Result<IpcMessage, _> = serde_json::from_str(body);
    assert!(parsed.is_err());
}
