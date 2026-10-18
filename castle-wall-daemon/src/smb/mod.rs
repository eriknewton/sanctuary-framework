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
        serde_json::from_slice(&std::fs::read(root.join(format!("{name}.json"))).unwrap()).unwrap()
    }
    fn emit(value: Value) {
        println!("SMB_RESULT {}", serde_json::to_string(&value).unwrap());
    }
    fn maximum(v: &Value) -> usize {
        match v.get("maximum") {
            Some(Value::String(name)) => constants::bound(name),
            Some(Value::Number(n)) => n.as_u64().unwrap() as usize,
            _ => constants::bound("REQ_MAX"),
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
        let maximum = constants::bound("GATE_B_PENDING_MAX");
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
            let bits: Vec<String> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
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
