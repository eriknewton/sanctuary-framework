// fail-before-exempt: the bounded bus response validator is new.
#![cfg(target_os = "linux")]
mod isolation;
use castle_wall_daemon::business_profile::writer_peer::{test_support::*, *};
use serde_json::Value;
use std::collections::BTreeSet;
#[test]
fn complete_corpus_has_exact_ids_and_refusals() {
    let corpus: Value =
        serde_json::from_str(include_str!("fixtures/writer_bus_replies.json")).unwrap();
    let rows = corpus["cases"].as_array().unwrap();
    let mut expected: BTreeSet<String> = [
        "captured-credentials",
        "captured-unit-id",
        "valid-response",
        "unknown-header",
        "wrong-serial",
        "wrong-sender",
        "wrong-destination",
        "wrong-header-type",
        "error-reply",
        "unexpected-message-type",
        "unix-fds",
        "descriptor-credential",
        "ignored-large-groups",
        "field-count",
        "registry-array-boundary",
        "registry-array-overflow",
        "nesting-overflow",
        "truncated-body",
        "trailing-body",
        "oversize-message",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for field in ["serial", "destination", "sender", "signature"] {
        for kind in ["missing", "duplicate"] {
            expected.insert(format!("{kind}-{field}"));
        }
    }
    for p in PROPERTY_REGISTRY {
        expected.insert(format!("property-{}-signature", p.member));
    }
    let actual: BTreeSet<String> = rows
        .iter()
        .map(|r| r["id"].as_str().unwrap().into())
        .collect();
    assert_eq!(rows.len(), actual.len());
    assert_eq!(actual, expected);
    for row in rows {
        let bytes = hex::decode(row["packet_hex"].as_str().unwrap()).unwrap();
        let serial = row["serial"].as_u64().unwrap() as u32;
        let sender = row["sender"].as_str().unwrap();
        let dest = row["destination"].as_str().unwrap();
        let observed = if let Some(member) = row["member"].as_str() {
            parse_property(&bytes, serial, sender, dest, member)
        } else {
            parse_response(
                &bytes,
                row["registry"].as_bool().unwrap(),
                serial,
                sender,
                dest,
                row["signature"].as_str().unwrap(),
            )
        };
        assert!(
            observed.fields <= BUS_HEADER_FIELDS_MAX,
            "field work exceeded cap: {}",
            row["id"]
        );
        assert!(
            observed.depth <= BUS_NESTING_MAX,
            "nesting work exceeded cap: {}",
            row["id"]
        );
        assert!(observed.bytes <= BUS_MESSAGE_MAX_BYTES);
        let outcome = match observed.result {
            Ok(()) => "ACCEPT".into(),
            Err(e) => format!("{e:?}"),
        };
        assert_eq!(outcome, row["refusal"].as_str().unwrap(), "{}", row["id"]);
        if row["id"].as_str().unwrap().starts_with("captured-") {
            assert!(row["provenance"].as_str().unwrap().starts_with("captured "));
        } else {
            assert_eq!(row["provenance"], "synthetic");
        }
    }
}

#[test]
fn matching_serial_from_another_sender_refuses() {
    let corpus: Value =
        serde_json::from_str(include_str!("fixtures/writer_bus_replies.json")).unwrap();
    let row = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "wrong-sender")
        .unwrap();
    let bytes = hex::decode(row["packet_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        parse_response(&bytes, false, 1, ":1.88", ":1.77", "s").result,
        Err(Error::Sender)
    );
}
