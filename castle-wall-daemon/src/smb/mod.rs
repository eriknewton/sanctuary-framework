//! Shared SMB contracts and codecs. Built, acceptance pending; no enforcement claim.
pub mod constants;
pub mod frame;
pub mod jcs;
#[cfg(unix)]
pub mod peer;
pub mod strict_json;
#[cfg(feature = "smb-test-hooks")]
pub mod test_hooks;
pub mod wire;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    // Must match server/test/smb/contracts.test.ts: each named witness emits the
    // real Rust results after asserting its own expected outcomes.
    fn fixture(name: &str) -> Value {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../server/test/smb/vectors");
        strict_json::fixture(&std::fs::read(root.join(format!("{name}.json"))).unwrap())
    }
    fn emit(value: Value) {
        println!("SMB_RESULT {}", jcs::encode(&value).unwrap());
    }
    fn maximum(v: &Value) -> usize {
        match v.get("maximum") {
            Some(Value::String(name)) => constants::bound(name).unwrap(),
            Some(Value::Number(n)) => n.as_u64().unwrap() as usize,
            _ => constants::bound("REQ_MAX").unwrap(),
        }
    }
    fn wire_vectors(group: &str) {
        let vectors = fixture("wire");
        let mut results = Vec::new();
        for v in vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["group"] == group)
        {
            let mut raw = v
                .get("raw")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| jcs::encode(&v["value"]).unwrap());
            if v["inflate"] == true {
                raw = " ".repeat(maximum(v)) + &raw;
            }
            let accepted =
                wire::validate_bytes(v["schema"].as_str().unwrap(), raw.as_bytes(), maximum(v))
                    .is_ok();
            assert_eq!(accepted, v["valid"].as_bool().unwrap(), "{}", v["name"]);
            results.push(json!({"name":v["name"],"accepted":accepted}));
        }
        assert!(!results.is_empty());
        emit(Value::Array(results));
    }
    #[test]
    #[ignore = "requires SMB_RELEASE_HOOK_SCAN=1 and the Linux packaging toolchain"]
    fn release_hook_scan() {
        // Ignoring keeps an unrequested packaging drill visible instead of reporting a pass.
        assert_eq!(std::env::var("SMB_RELEASE_HOOK_SCAN").as_deref(), Ok("1"));
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let status = std::process::Command::new("bash")
            .arg(root.join("scripts/smb/release-hook-scan.sh"))
            .current_dir(root)
            .status()
            .expect("release scan process");
        assert!(status.success(), "release scan must pass");
    }
    #[test]
    fn codec_bounds_agree() {
        let vectors = fixture("bounds");
        let mut results = Vec::new();
        for v in vectors["depth"].as_array().unwrap() {
            let depth = constants::bound("JSON_MAX_DEPTH").unwrap()
                + v["offset"].as_u64().unwrap() as usize;
            let mut value = if v["shape"] == "array" {
                json!([])
            } else {
                json!({})
            };
            let mut raw = if v["shape"] == "array" {
                "[]".to_owned()
            } else {
                "{}".to_owned()
            };
            for _ in 0..depth {
                if v["shape"] == "array" {
                    value = json!([value]);
                    raw = format!("[{raw}]");
                } else {
                    value = json!({"a":value});
                    raw = format!("{{\"a\":{raw}}}");
                }
            }
            let encoded = jcs::encode(&value).is_ok();
            let parsed =
                strict_json::parse(raw.as_bytes(), constants::bound("REQ_MAX").unwrap()).is_ok();
            assert_eq!(encoded, v["valid"].as_bool().unwrap(), "{}", v["name"]);
            assert_eq!(parsed, encoded);
            results.push(json!({"encoded":encoded,"parsed":parsed}));
        }
        for v in vectors["numbers"].as_array().unwrap() {
            // Build an exact u64 value without first rounding through binary64.
            let value = Value::from(v["literal"].as_str().unwrap().parse::<u64>().unwrap());
            let accepted = jcs::encode(&value).is_ok();
            assert_eq!(accepted, v["valid"].as_bool().unwrap());
            results.push(json!(accepted));
        }
        emit(json!(results));
    }
    #[test]
    fn wire_unknown_schema_refuses() {
        wire_vectors("unknown");
    }
    #[test]
    fn normalize_boot_id_agrees() {
        let uuid = "ABCDEF01-2345-6789-ABCD-EF0123456789";
        assert_eq!(
            wire::normalize_boot_id(uuid).unwrap(),
            "abcdef0123456789abcdef0123456789"
        );
        assert!(wire::normalize_boot_id("not-a-uuid").is_err());
        emit(json!(true));
    }
    #[test]
    fn fifo_result_encoded_bound() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let encoded_max = constants::bound("FIFO_RESULT_ENCODED_MAX").unwrap();
        let decoded_max = encoded_max / constants::bound("BASE64_OUTPUT").unwrap()
            * constants::bound("BASE64_INPUT").unwrap();
        for v in fixture("bounds")["fifo"].as_array().unwrap() {
            let extra = v["extra_decoded_bytes"].as_u64().unwrap() as usize;
            let value =
                json!({"type":"result","data_b64":STANDARD.encode(vec![0; decoded_max + extra])});
            assert_eq!(
                wire::validate("fifo_result", &value),
                v["valid"].as_bool().unwrap()
            );
            if extra == 0 {
                assert!(frame::encode(
                    &value,
                    "fifo_result",
                    constants::bound("TASK_OUT_FRAME_MAX").unwrap()
                )
                .is_ok());
            }
        }
        emit(json!(true));
    }
    #[test]
    fn embedded_schema_inventory() {
        fn check(spec: &Value, visiting: &mut std::collections::BTreeSet<String>) {
            if let Some(name) = spec
                .as_str()
                .or_else(|| spec.get("ref").and_then(Value::as_str))
            {
                assert!(visiting.insert(name.into()), "schema reference cycle");
                let target = wire::source()["schemas"].get(name).expect("schema name");
                check(target, visiting);
                visiting.remove(name);
                return;
            }
            let spec = spec.as_object().expect("schema object");
            if spec.contains_key("const") {
                return;
            }
            if let Some(values) = spec.get("enum") {
                assert!(values.is_array());
                return;
            }
            if let Some(alternatives) = spec.get("oneOf") {
                for item in alternatives.as_array().expect("oneOf array") {
                    check(item, visiting);
                }
                return;
            }
            let check_bound = |value: &Value| {
                if let Some(number) = value.as_u64() {
                    assert!(usize::try_from(number).is_ok());
                } else {
                    assert!(constants::bound(value.as_str().expect("bound name")).is_ok());
                }
            };
            match spec["type"].as_str().expect("schema type") {
                "object" => {
                    if let Some(parent) = spec.get("extends") {
                        check(parent, visiting);
                        let mut parent = parent;
                        while let Some(name) = parent
                            .as_str()
                            .or_else(|| parent.get("ref").and_then(Value::as_str))
                        {
                            parent = &wire::source()["schemas"][name];
                        }
                        assert_eq!(parent["type"], "object", "extends must supply fields");
                    }
                    for field in spec["fields"].as_object().expect("fields object").values() {
                        check(field, visiting);
                    }
                }
                "array" => {
                    check_bound(&spec["max"]);
                    check(&spec["items"], visiting);
                }
                "decimal" => {
                    assert!(spec["max"]
                        .as_str()
                        .expect("decimal max string")
                        .parse::<u64>()
                        .is_ok());
                    if let Some(min) = spec.get("min") {
                        assert!(min
                            .as_str()
                            .expect("decimal min string")
                            .parse::<u64>()
                            .is_ok());
                    }
                }
                "string" => {
                    check_bound(&spec["min"]);
                    check_bound(&spec["max"]);
                    if let Some(chars) = spec.get("chars") {
                        assert!(chars.is_string());
                    }
                    if let Some(prefix) = spec.get("prefix") {
                        assert!(constants::value(prefix.as_str().expect("prefix name"))
                            .unwrap()
                            .is_string());
                        check(&spec["suffix"], visiting);
                    }
                }
                "base64" | "base64url" => {
                    check_bound(&spec["max"]);
                    if let Some(max) = spec.get("encoded_max") {
                        check_bound(max);
                    }
                }
                operation => assert!(["integer", "json"].contains(&operation)),
            }
        }
        for spec in wire::source()["schemas"].as_object().unwrap().values() {
            check(spec, &mut std::collections::BTreeSet::new());
        }
        for edge in wire::source()["edges"].as_object().unwrap().values() {
            for name in ["pending_max", "frame_max"] {
                if let Some(number) = edge[name].as_u64() {
                    assert!(usize::try_from(number).is_ok());
                } else {
                    assert!(constants::bound(edge[name].as_str().unwrap()).is_ok());
                }
            }
            for route in edge["requests"].as_object().unwrap().values() {
                for direction in ["request", "reply"] {
                    let name = route[direction].as_str().expect("route schema name");
                    assert!(wire::source()["schemas"].get(name).is_some());
                }
            }
        }
    }
    #[test]
    fn runtime_refusals_agree() {
        assert!(constants::value("missing_constant").is_err());
        for name in [
            "missing_constant",
            "PLACEHOLDER_PREFIX",
            "AGENT_WRITE_SET",
            "AGENT_UNIT_PROPERTIES",
        ] {
            assert!(constants::bound(name).is_err());
        }
        assert!(!wire::validate("missing_schema", &json!({})));
        // 16 byte pairs encode a 128-bit identity as 32 hex characters.
        let request = json!({"kind":"scope", "id":"1", "I":"ab".repeat(16), "C":"1"});
        let good = json!({"id":"1", "ok":false, "error":"refused"});
        for id in [
            Value::Null,
            json!(true),
            json!(1),
            json!([]),
            json!({}),
            json!("unknown"),
        ] {
            let mut malformed = request.clone();
            malformed["id"] = id.clone();
            let mut matcher = wire::ReplyMatcher::new("gate-b").unwrap();
            assert!(matcher.register(&malformed).is_err());
            assert_eq!(matcher.state, wire::ConnectionState::Closed);
            assert_eq!(matcher.outstanding(), 0);
            let mut matcher = wire::ReplyMatcher::new("gate-b").unwrap();
            matcher.register(&request).unwrap();
            let mut reply = good.clone();
            reply["id"] = id;
            assert!(matcher.receive(&reply).is_err());
            assert_eq!(matcher.state, wire::ConnectionState::Closed);
            assert_eq!(matcher.outstanding(), 0);
        }
        for malformed in [
            json!({"kind":"missing_route", "id":"1"}),
            json!({"kind":false, "id":"1"}),
            json!({"id":"1"}),
            json!({"kind":"scope"}),
            Value::Null,
        ] {
            let mut matcher = wire::ReplyMatcher::new("gate-b").unwrap();
            assert!(matcher.register(&malformed).is_err());
            assert_eq!(matcher.state, wire::ConnectionState::Closed);
            assert_eq!(matcher.outstanding(), 0);
        }
        let mut matcher = wire::ReplyMatcher::new("gate-b").unwrap();
        assert!(matcher.receive(&good).is_err());
        assert_eq!(matcher.state, wire::ConnectionState::Closed);
        emit(json!(true));
    }
    #[test]
    fn constants_parity() {
        emit(json!({"constants":constants::all(), "wire":wire::source()}));
    }
    #[test]
    fn wire_vectors_agree() {
        wire_vectors("wire");
    }
    #[test]
    fn wire_event_has_one_discriminator() {
        wire_vectors("event");
    }
    #[test]
    fn wire_pins_128_bit_ids_hex_and_class_string() {
        wire_vectors("ids");
    }
    fn strict_vectors(group: &str) {
        let vectors = fixture("strict-json");
        let mut results = Vec::new();
        for v in vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["group"] == group)
        {
            let bytes = v
                .get("hex")
                .and_then(Value::as_str)
                .map(|s| hex::decode(s).unwrap())
                .unwrap_or_else(|| v["raw"].as_str().unwrap().as_bytes().to_vec());
            let parsed = strict_json::parse(&bytes, maximum(v));
            let accepted = parsed.as_ref().is_ok_and(|value| {
                v.get("schema").map_or(true, |schema| {
                    wire::validate(schema.as_str().unwrap(), value)
                })
            });
            assert_eq!(accepted, v["valid"].as_bool().unwrap(), "{}", v["name"]);
            let canonical = if accepted {
                Some(jcs::encode(&parsed.unwrap()).unwrap())
            } else {
                None
            };
            if accepted && v["expected"].is_string() {
                assert_eq!(
                    canonical.as_deref(),
                    v["expected"].as_str(),
                    "{}",
                    v["name"]
                );
            }
            results.push(json!({"name":v["name"],"accepted":accepted,"canonical":canonical}));
        }
        assert!(!results.is_empty());
        emit(Value::Array(results));
    }
    #[test]
    fn strict_json_numeric_domain_agrees() {
        strict_vectors("numeric_domain");
    }
    #[test]
    fn strict_json_vectors_agree() {
        strict_vectors("syntax");
    }
    #[test]
    fn jcs_rfc8785_appendix_b() {
        let vectors = fixture("jcs");
        let mut results = Vec::new();
        for v in vectors["numbers"].as_array().unwrap() {
            let value =
                f64::from_bits(u64::from_str_radix(v["bits"].as_str().unwrap(), 16).unwrap());
            let result = jcs::number(value).ok();
            assert_eq!(result.as_deref(), v["expected"].as_str(), "{}", v["bits"]);
            results.push(json!({"bits":v["bits"],"canonical":result}));
        }
        emit(Value::Array(results));
    }
    #[test]
    fn jcs_documents_agree() {
        let vectors = fixture("jcs");
        let mut results = Vec::new();
        for v in vectors["documents"].as_array().unwrap() {
            let result = jcs::encode(&v["value"]).unwrap();
            assert_eq!(result, v["expected"]);
            results.push(Value::String(result));
        }
        emit(Value::Array(results));
    }
    #[test]
    fn frame_vectors_agree() {
        let vectors = fixture("frame");
        let mut results = Vec::new();
        for v in vectors["vectors"].as_array().unwrap() {
            let bytes = hex::decode(v["hex"].as_str().unwrap()).unwrap();
            let schema = v["schema"].as_str().unwrap();
            let accepted = frame::decode(&bytes, schema, maximum(v)).is_ok();
            assert_eq!(accepted, v["valid"].as_bool().unwrap(), "{}", v["name"]);
            if accepted {
                assert_eq!(
                    frame::encode(&v["value"], schema, maximum(v)).unwrap(),
                    bytes
                );
            }
            results.push(json!({"name":v["name"],"accepted":accepted}));
        }
        emit(Value::Array(results));
    }
    #[test]
    fn reply_matcher_fails_closed() {
        let request =
            json!({"kind":"scope","id":"1","I":"abababababababababababababababab","C":"1"});
        let good = json!({"id":"1","ok":false,"error":"refused"});
        let mut results = Vec::new();
        for reply in [
            json!({"id":"2","ok":false,"error":"refused"}),
            json!({"id":"1","ok":true}),
        ] {
            let mut matcher = wire::ReplyMatcher::new("gate-b").unwrap();
            matcher.register(&request).unwrap();
            assert!(matcher.receive(&reply).is_err());
            assert_eq!(matcher.outstanding(), 0);
            assert_eq!(matcher.state, wire::ConnectionState::Closed);
            results.push(true);
        }
        let mut matcher = wire::ReplyMatcher::new("gate-b").unwrap();
        matcher.register(&request).unwrap();
        assert!(matcher.receive(&good).is_ok());
        assert!(matcher.receive(&good).is_err());
        assert_eq!(matcher.state, wire::ConnectionState::Closed);
        results.push(true);
        emit(json!(results));
    }
    #[test]
    fn reply_matcher_bounded_waves() {
        let maximum = constants::bound("GATE_B_PENDING_MAX").unwrap();
        for _wave in 0..3 {
            // Repeated admission, closure and late-completion schedules.
            let mut matcher = wire::ReplyMatcher::new("gate-b").unwrap();
            for id in 1..=maximum {
                matcher.register(&json!({"kind":"await","id":id.to_string(),"Q":"abababababababababababababababab"})).unwrap();
            }
            assert!(matcher.register(&json!({"kind":"await","id":(maximum+1).to_string(),"Q":"abababababababababababababababab"})).is_err());
            assert_eq!(matcher.outstanding(), 0);
            assert!(matcher
                .receive(&json!({"id":"1","ok":false,"error":"refused"}))
                .is_err());
        }
        emit(json!(true));
    }
    #[test]
    fn number_differential_runner() {
        // Optional batch transport for the TypeScript randomized serializer comparison.
        // The normative Appendix B and parser tests above always run without this transport.
        if let Ok(path) = std::env::var("SMB_NUMBER_INPUT") {
            let bits: Vec<String> = strict_json::fixture(&std::fs::read(path).unwrap());
            emit(Value::Array(
                bits.iter()
                    .map(|bits| {
                        jcs::number(f64::from_bits(u64::from_str_radix(bits, 16).unwrap()))
                            .map(Value::String)
                            .unwrap_or(Value::Null)
                    })
                    .collect(),
            ));
        }
    }
}
