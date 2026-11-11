// fail-before-exempt: the bounded bus response validator is new.
#![cfg(target_os = "linux")]
mod isolation;
use castle_wall_daemon::business_profile::writer_peer::{test_support::*, *};
use serde_json::Value;
use std::collections::BTreeMap;
#[test]
fn complete_corpus_has_exact_ids_and_refusals() {
    let corpus: Value =
        serde_json::from_str(include_str!("fixtures/writer_bus_replies.json")).unwrap();
    let rows = corpus["cases"].as_array().unwrap();
    let mut expected: BTreeMap<String, String> = [
        ("captured-credentials", "ACCEPT"),
        ("captured-unit-id", "ACCEPT"),
        ("valid-response", "ACCEPT"),
        ("unknown-header", "Header"),
        ("wrong-serial", "Serial"),
        ("wrong-sender", "Sender"),
        ("wrong-destination", "Destination"),
        ("wrong-header-type", "Header"),
        ("error-reply", "MessageType"),
        ("unexpected-message-type", "MessageType"),
        ("unix-fds", "Descriptors"),
        ("descriptor-credential", "Descriptors"),
        ("ignored-large-groups", "ACCEPT"),
        ("field-count", "Cap(\"fields\")"),
        ("registry-array-boundary", "ACCEPT"),
        ("registry-array-overflow", "Cap(\"array\")"),
        ("nesting-overflow", "Cap(\"nesting\")"),
        ("truncated-body", "Framing"),
        ("string-length-overflow", "Framing"),
        ("string-terminator", "Framing"),
        ("registry-element-shape", "Framing"),
        ("trailing-body", "Framing"),
        ("oversize-message", "Cap(\"bytes\")"),
    ]
    .into_iter()
    .map(|(id, refusal)| (id.to_owned(), refusal.to_owned()))
    .collect();
    for (field, refusal) in [
        ("serial", "Serial"),
        ("destination", "Destination"),
        ("sender", "Sender"),
        ("signature", "Signature"),
    ] {
        expected.insert(format!("missing-{field}"), refusal.into());
        expected.insert(format!("duplicate-{field}"), "Header".into());
    }
    for p in PROPERTY_REGISTRY {
        expected.insert(
            format!("property-{}-signature", p.member),
            "Signature".into(),
        );
    }
    let actual: BTreeMap<String, String> = rows
        .iter()
        .map(|r| {
            (
                r["id"].as_str().unwrap().into(),
                r["refusal"].as_str().unwrap().into(),
            )
        })
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
